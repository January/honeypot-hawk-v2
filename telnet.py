import asyncio
import csv
import datetime
import os.path as path
import psutil
import requests
import socket
import telnetlib3
import yaml

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# Load port from config file
listen_port = config['telnet_port']

# Machine's hostname, useful when impersonating a real Unix login prompt
hostname = socket.gethostname()

# Will be printed when trap is sprung
message = config['telnet_message']

# AbuseIPDB endpoint
abipdb_endpoint = "https://api.abuseipdb.com/api/v2/report"

async def honeypot(reader, writer):
    username = ""
    writer.write(f"{config['telnet_login_prompt']}{hostname} login: ")
    while True:
        # Act like we're reading a username
        outp = await reader.read(1)
        if not outp:
            break
        elif '\r' in outp:
            # Horribly inefficient due to lack of an inbuilt function to get client IP
            client_ip = "Unknown"
            current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            p = psutil.Process()
            for c in p.connections(kind='inet'):
                if c.status == "ESTABLISHED" and c.laddr.port == listen_port:
                    client_ip = c.raddr.ip

            ip_country = "Unknown"
            ip_region = "Unknown"
            ip_city = "Unknown"
            ip_isp = "Unknown"

            # Only do this if we actually know the IP, otherwise leave everything unknown
            if client_ip != "Unknown":
                url = f"http://ip-api.com/json/{client_ip}"
                resp = requests.get(url=url).json()
                if(resp['status'] == 'success'):
                    ip_country = resp['country']
                    ip_region = resp['regionName']
                    ip_city = resp['city']
                    ip_isp = resp['isp']
            # Log the attempt in console if enabled
            if config['console_logging']:
                print(f"[{current_time}] {client_ip} ({ip_city}, {ip_region}, {ip_country}) tried logging in as {username}")
            # Log the attempt in a CSV file if enabled
            if config['csv_logging']:
                with open("attempts.csv", 'a', newline='') as attempt:
                    outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
                    outfile.writerow([current_time, username, client_ip, ip_country, ip_region, ip_city, ip_isp])
            # Report attempt to AbuseIPDB if enabled
            if config['abuseipdb_enable']:
                report_data = {"ip": client_ip, "categories": "18", "comment": f"Attempted telnet login on port {listen_port} with username {username}", "key": config['abuseipdb_key']}
                requests.post(abipdb_endpoint, json=report_data)

            writer.write(message) # Send user a message after failing the login
            break
        else:
            username += outp
            writer.write(outp)
    writer.close()

# Create a new CSV log file if it's enabled and doesn't exist already
if config['csv_logging'] and not path.exists("attempts.csv"):
    with open("attempts.csv", 'w', newline='') as atts:
        initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
        initial.writerow(["Time", "Username", "IP", "Country", "Region", "City", "ISP"])

loop = asyncio.get_event_loop()
coro = telnetlib3.create_server(port=listen_port, shell=honeypot, timeout=20)
start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"[{start_time}] Simple Telnet Honeypot running!")
telnet_server = loop.run_until_complete(coro)
loop.run_until_complete(telnet_server.wait_closed())