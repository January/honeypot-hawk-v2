# This is the original port scan detector that all the other honeypots in this folder are based off of.
# It was written on October 9, 2021, and was written for a friend, who suspected that an unknown-to-him
# intruder into his "private" Minecraft server utilized a port scanner to find the server. Nevermind the
# fact that there was no whitelist and 25565 is the default port... however, it did confirm that the original
# intruder/griefer used a port scanner to find the server, for what it's worth.
# I made some slight changes in 2023 to bring it more in-line with the others. But otherwise, this version
# of the honeypot is as basic as it gets. Play around with it, customize it however you want.

import asyncio
import datetime
import os
import requests
import sys

abipdb_token = "AbuseIPDB token goes here."

port = 25565

abipdb_endpoint = "https://api.abuseipdb.com/api/v2/report"

# List of recently caught IPs, meant to avoid duplicate reports on AbuseIPDB
# as to not exhaust the daily report allowance early because of duplicates
ip_list = []

async def honeypot(reader, writer):
    client_ip = writer.get_extra_info('peername')[0]
    url = f"http://ip-api.com/json/{client_ip}"
    resp = requests.get(url=url).json()
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if(resp['status'] == 'success'):
        ip_country = resp['country']
        ip_region = resp['regionName']
        ip_city = resp['city']
    print(f"[{current_time}] {client_ip} ({ip_city}, {ip_region}, {ip_country}) connected to port {port}")
    if client_ip not in ip_list: # Check if this IP is in the last n that were reported
        if len(ip_list) == 10:
            ip_list.pop(0)
        ip_list.append(client_ip)
        report_data = {"ip": client_ip, "categories": "21", "comment": f"Minecraft server crawler (scanned port {port})", "key": abipdb_token}
        requests.post(abipdb_endpoint, json=report_data)

try:
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.start_server(honeypot, '', port))
    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{start_time}] Basic Single-Port Honeypot running! Press Ctrl+C to quit.")
    loop.run_forever()
except KeyboardInterrupt:
    end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{end_time}] Quitting.")
    try:
        sys.exit(130)
    except SystemExit:
        os._exit(130)