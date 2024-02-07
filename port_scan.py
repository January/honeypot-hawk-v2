import asyncio
import csv
import datetime
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

def ip_exists(key):
    for i in suspect_ips:
        if key in i['ip']:
            return i
        else:
            return False

def log_report(info):
    ip = info['ip']
    ip_country = "Unknown"
    ip_region = "Unknown"
    ip_city = "Unknown"
    ip_isp = "Unknown"

    # Gather location data using IP-API
    url = f"http://ip-api.com/json/{ip}"
    resp = requests.get(url=url).json()
    if(resp['status'] == 'success'):
        ip_country = resp['country']
        ip_region = resp['regionName']
        ip_city = resp['city']
        ip_isp = resp['isp']

    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ports = ", ".join(str(p) for p in list(set(info['ports'])))

    if config['console_logging']:
        print(f"[Port-scan @ {current_time}] {ip} ({ip_city}, {ip_region}, {ip_country}) tried scanning port(s) {ports}")
    if config['csv_logging']:
        with open(csv_outfile, 'a', newline='') as attempt:
            outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
            outfile.writerow([current_time, ip, ip_country, ip_region, ip_city, ip_isp, ports])
    # Report attempt to AbuseIPDB if enabled
    if config['abuseipdb_enable']:
        if ip not in ip_list: # Check if this IP is in the last n that were reported
            if len(ip_list) == config['ip_log']:
                ip_list.pop(0)
            ip_list.append(ip)
            report_data = {"ip": ip, "categories": "14", "comment": f"Attempted port scan. Scanned port(s): {ports}", "key": config['abuseipdb_key']}
            requests.post(abipdb_endpoint, json=report_data)

# Clean out our tracking array for attempts that might not be scanners every 15 minutes
async def clean_suspects():
     while True:
        for i in suspect_ips:
            if i['attempts'] < config['portscan_strikes'] and i['timestamp'] + 1800 < time.time():
                suspect_ips.remove(i)
        await asyncio.sleep(900)

async def honeypot(reader, writer):
    client_ip = writer.get_extra_info('peername')[0]
    port = writer.get_extra_info('sockname')[1]

    # Check if we've already tracked this IP. If so, increase scan attempts
    offset = ip_exists(client_ip)
    if offset:
        offset['attempts'] += 1
        offset['ports'].append(port)
        # If we've reached the 'strikes,' assume it's a scanner and report it
        if offset['attempts'] >= config['portscan_strikes']:
            log_report(offset)
            suspect_ips.remove(offset)
    else:
        # If not, make a new entry
        suspect_ips.append({"ip": client_ip, "attempts": 1, "ports": [port], "timestamp": time.time()})
    writer.close()

# Create a new CSV log file if it's enabled and doesn't exist already
if config['csv_logging'] and not os.path.exists(csv_outfile):
    with open(csv_outfile, 'w', newline='') as atts:
        initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
        initial.writerow(["Time", "IP", "Country", "Region", "City", "ISP", "Ports"])

def run_port_scan():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for port in ports:
            loop.run_until_complete(asyncio.start_server(honeypot, '', port))
        loop.create_task(clean_suspects())
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{start_time}] Simple Port-Scan Honeypot running! Press Ctrl+C to quit.")
        loop.run_forever()
    except KeyboardInterrupt:
        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{end_time}] Quitting.")
        try:
            sys.exit(130)
        except SystemExit:
            os._exit(130)