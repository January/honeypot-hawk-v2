import asyncio
import csv
import datetime
from dateutil.parser import isoparse
import json
import os
import requests
import socket
import sys
import telnetlib3
import time
import yaml

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# CSV log name
csv_outfile = config['telnet_csv_name']

# Load port from config file
listen_port = config['telnet_port']

# Machine's hostname, useful when impersonating a real Unix login prompt
hostname = socket.gethostname()

# Will be printed when trap is sprung
message = config['telnet_message']

# AbuseIPDB endpoint
abipdb_endpoint = "https://api.abuseipdb.com/api/v2/report"

reports_endpoint = "https://api.abuseipdb.com/api/v2/reports"

# Load AbuseIPDB UID
abipdb_uid = config['abuseipdb_uid']

# List of recently caught IPs, meant to avoid duplicate reports on AbuseIPDB
# as to not exhaust the daily report allowance early because of duplicates
ip_list = []

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

async def honeypot(reader, writer):
    username = ""
    writer.write(f"{config['telnet_login_prompt']}{hostname} login: ")
    while True:
        try:
        # Act like we're reading a username
            outp = await reader.read(1)
            if not outp:
                break
            elif '\r' in outp:
                # The attacker has pressed enter, so log and report the attempt
                client_ip = writer.get_extra_info('peername')[0]
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ip_country = "Unknown"
                ip_region = "Unknown"
                ip_city = "Unknown"
                ip_isp = "Unknown"

                # Gather location data using IP-API
                url = f"http://ip-api.com/json/{client_ip}"
                resp = requests.get(url=url).json()
                if(resp['status'] == 'success'):
                    ip_country = resp['country']
                    ip_region = resp['regionName']
                    ip_city = resp['city']
                    ip_isp = resp['isp']
                # Log the attempt in console if enabled
                if config['console_logging']:
                    print(f"[Telnet @ {current_time}] {client_ip} ({ip_city}, {ip_region}, {ip_country}) tried logging in as {username}")
                # Log the attempt in a CSV file if enabled
                if config['csv_logging']:
                    with open(csv_outfile, 'a', newline='') as attempt:
                        outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
                        outfile.writerow([current_time, username, client_ip, ip_country, ip_region, ip_city, ip_isp])
                # Report attempt to AbuseIPDB if enabled
                if config['abuseipdb_enable']:
                    if not ip_in_list(client_ip): # Check if this IP was reported in the last 15 minutes
                        if not check_reports(client_ip):
                            ip_list.append({"ip": client_ip, "timestamp": time.time()})
                            utc_time = datetime.datetime.utcnow().strftime("%H:%M")
                            report_data = {"ip": client_ip, "categories": "18", "comment": f"[{utc_time}] Attempted telnet login on port {listen_port} with username {username}", "key": config['abuseipdb_key']}
                            repost = requests.post(abipdb_endpoint, json=report_data)
                            if "errors" in json.loads(repost.text):
                                log_failed_report(report_data)
                writer.write(message) # Send user a message after failing the login
                break
            else:
                username += outp
                writer.write(outp)
        except ConnectionResetError:
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            client_ip = writer.get_extra_info('peername')[0]
            print(f"[Telnet @ {current_time}] Connection error from {client_ip}. Ignoring.")
    writer.close()

# Remove IPs that haven't been reported in fifteen minutes.
async def clean_ip_list():
     while True:
        for i in ip_list:
            if i['timestamp'] + 900 < time.time():
                ip_list.remove(i)
        await asyncio.sleep(60)

def run_honeypot():
    try:
        # Create a new CSV log file if it's enabled and doesn't exist already
        if config['csv_logging'] and not os.path.exists(csv_outfile):
            with open(csv_outfile, 'w', newline='') as atts:
                initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
                initial.writerow(["Time", "Username", "IP", "Country", "Region", "City", "ISP"])
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.create_task(clean_ip_list())
        coro = telnetlib3.create_server(port=listen_port, shell=honeypot, timeout=20)
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[Telnet @ {start_time}] Telnet honeypot running!")
        telnet_server = loop.run_until_complete(coro)
        loop.run_until_complete(telnet_server.wait_closed())
    except KeyboardInterrupt:
        end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[Telnet @ {end_time}] Stopping telnet honeypot.")
        try:
            sys.exit(129)
        except SystemExit:
            os._exit(129)