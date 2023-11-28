import asyncio
import csv
import datetime
import os
import requests
import sys
import yaml

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# Load ports from config
ports = config['portscan_ports']

async def honeypot(reader, writer):
    client_ip = writer.get_extra_info('peername')[0]
    port = writer.get_extra_info('sockname')[1]
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ip_country = "Unknown"
    ip_region = "Unknown"
    ip_city = "Unknown"
    ip_isp = "Unknown"

    # Get location data using IP-API
    url = f"http://ip-api.com/json/{client_ip}"
    resp = requests.get(url=url).json()
    if(resp['status'] == 'success'):
        ip_country = resp['country']
        ip_region = resp['regionName']
        ip_city = resp['city']
        ip_isp = resp['isp']

    if config['console_logging']:
        print(f"[{current_time}] {client_ip} ({ip_city}, {ip_region}, {ip_country}) connected to port {port}")
    writer.close()
    await writer.wait_closed()

try:
    loop = asyncio.get_event_loop()
    for port in ports:
        loop.run_until_complete(asyncio.start_server(honeypot, '', port))
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