import asyncio
import csv
import datetime
import os
import requests
import socket
import sys
import telnetlib3
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

# List of recently caught IPs, meant to avoid duplicate reports on AbuseIPDB
# as to not exhaust the daily report allowance early because of duplicates
ip_list = []

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
                    if client_ip not in ip_list: # Check if this IP is in the last n that were reported
                        if len(ip_list) == config['ip_log']:
                            ip_list.pop(0)
                        ip_list.append(client_ip)
                        report_data = {"ip": client_ip, "categories": "18", "comment": f"Attempted telnet login on port {listen_port} with username {username}", "key": config['abuseipdb_key']}
                        requests.post(abipdb_endpoint, json=report_data)

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

def run_honeypot():
    try:
        # Create a new CSV log file if it's enabled and doesn't exist already
        if config['csv_logging'] and not os.path.exists(csv_outfile):
            with open(csv_outfile, 'w', newline='') as atts:
                initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
                initial.writerow(["Time", "Username", "IP", "Country", "Region", "City", "ISP"])
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
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