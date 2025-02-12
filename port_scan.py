import asyncio
import csv
import datetime
from dateutil.parser import isoparse
import json
import os
import requests
import sys
import time
import yaml

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# File for CSV logging
csv_outfile = config['portscan_csv_name']

# Load ports from config
ports = config['portscan_ports']

# IPs that have accessed the open ports
suspect_ips = []

# List of recently caught IPs, meant to avoid duplicate reports on AbuseIPDB
# as to not exhaust the daily report allowance early because of duplicates
ip_list = []

# AbuseIPDB endpoint
abipdb_endpoint = "https://api.abuseipdb.com/api/v2/report"

reports_endpoint = "https://api.abuseipdb.com/api/v2/reports"

# Load AbuseIPDB UID
abipdb_uid = config['abuseipdb_uid']

def ip_suspect(key):
    for i in suspect_ips:
        if key in i['ip']:
            return i
    return False

def ip_in_list(key):
    for i in ip_list:
        if key in i['ip']:
            return i
    return False

def check_reports(ip):
    resp = requests.get(url=f"{reports_endpoint}?ipAddress={ip}&maxAgeInDays=1&perPage=50&key={config['abuseipdb_key']}").json()
    if "data" in resp:
        for result in resp['data']['results']:
            if result['reporterId'] == abipdb_uid:
                report_timestamp = isoparse(result['reportedAt']).timestamp()
                if time.time() - report_timestamp > 900:
                    return False
                else:
                    return True
        return False
    else:
        return False

def log_failed_report(report_data):
    current_time = datetime.datetime.utcnow()
    current_date = current_time.date()
    filename = f"failed_reports_{current_date}.csv"

    if not os.path.isfile(filename):
        with open(filename, 'w', newline='') as reports:
            initial = csv.writer(reports, quoting=csv.QUOTE_MINIMAL)
            initial.writerow(["IP", "Categories", "ReportDate", "Comment"])

    with open(filename, 'a', newline='') as reports:
        report = csv.writer(reports, quoting=csv.QUOTE_MINIMAL)
        report.writerow([report_data['ip'], report_data['categories'], current_time.isoformat(), report_data['comment']])

async def rerun_on_exception(coro, *args, **kwargs):
    while True:
        try:
            await coro(*args, **kwargs)
        except Exception:
            pass

def log_report(info):
    ip = info['ip']
    ip_country = info['country']
    ip_region = info['region']
    ip_city = info['city']
    ip_isp = info['isp']

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ports = ", ".join(("TCP/" + str(p)) for p in list(set(info['ports'])))

    if config['console_logging']:
        print(f"[Port-scan @ {current_time}] {ip} ({ip_city}, {ip_region}, {ip_country}) tried scanning port(s) {ports}")
    if config['csv_logging']:
        with open(csv_outfile, 'a', newline='') as attempt:
            outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
            outfile.writerow([current_time, ip, ip_country, ip_region, ip_city, ip_isp, ports])
    # Report attempt to AbuseIPDB if enabled
    if config['abuseipdb_enable']:
        if not ip_in_list(ip): # Check if this IP was reported in the last 15 minutes
            if not check_reports(ip):
                ip_list.append({"ip": ip, "timestamp": time.time()})
                utc_time = datetime.datetime.utcnow().strftime("%H:%M")
                report_data = {"ip": ip, "categories": "14", "comment": f"[{utc_time}] Port scanning. Port(s) scanned: {ports}", "key": config['abuseipdb_key']}
                repost = requests.post(abipdb_endpoint, json=report_data)
                if "errors" in json.loads(repost.text):
                    log_failed_report(report_data)

# Check every minute for reportable IPs, remove inactive ones.
async def clean_suspects():
     while True:
        for i in suspect_ips:
            if len(i['ports']) < config['portscan_strikes'] and i['timestamp'] + 1800 < time.time():
                suspect_ips.remove(i)
            elif len(i['ports']) >= config['portscan_strikes']:
                log_report(i)
                suspect_ips.remove(i)
        for i in ip_list:
            if i['timestamp'] + 900 < time.time():
                ip_list.remove(i)
        await asyncio.sleep(30)

async def honeypot(reader, writer):
    client_ip = writer.get_extra_info('peername')[0]
    port = writer.get_extra_info('sockname')[1]

    # Check if we've already tracked this IP. If so, add to the ports we've seen it hit.
    offset = ip_suspect(client_ip)
    if offset:
        offset['ports'].append(port)
    else:
        # If not, make a new entry
        ip_country = "Unknown"
        ip_region = "Unknown"
        ip_city = "Unknown"
        ip_isp = "Unknown"
        url = f"http://ip-api.com/json/{client_ip}"
        resp = requests.get(url=url).json()
        if(resp['status'] == 'success'):
            ip_country = resp['country']
            ip_region = resp['regionName']
            ip_city = resp['city']
            ip_isp = resp['isp']
        suspect_ips.append({"ip": client_ip, "ports": [port], "timestamp": time.time(), "country": ip_country,
                            "region": ip_region, "city": ip_city, "isp": ip_isp})
    writer.close()
    await writer.wait_closed()

def run_honeypot():
    try:
        # Create a new CSV log file if it's enabled and doesn't exist already
        if config['csv_logging'] and not os.path.exists(csv_outfile):
            with open(csv_outfile, 'w', newline='') as atts:
                initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
                initial.writerow(["Time", "IP", "Country", "Region", "City", "ISP", "Ports"])

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for port in ports:
            loop.create_task(rerun_on_exception(asyncio.start_server, honeypot, '', port))
        loop.create_task(clean_suspects())
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[Port-scan @ {start_time}] Port scan honeypot running!")
        loop.run_forever()
    except KeyboardInterrupt:
        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[Port-scan @ {end_time}] Stopping port scan honeypot.")
        try:
            sys.exit(129)
        except SystemExit:
            os._exit(129)