import asyncio
import csv
import datetime
import os.path as path
import psutil
import requests
import socket
import telnetlib3

# Port the fake server will be listening on. Use 23 for maximum effect.
# Do note that you may need to be root to use port 23, though!
listen_port = 6023

# Machine's hostname, useful when impersonating a real login prompt
hostname = socket.gethostname()

# Example message to print when the trap has been sprung
message = "\r\nWhy are you trying to bruteforce telnet servers? That isn't very nice!\r\n"

async def honeypot(reader, writer):
    username = ""
    writer.write(f'Ubuntu 22.04.3 LTS\r\n{hostname} login: ')
    while True:
        # Act like we're reading a username
        outp = await reader.read(1)
        if not outp:
            break
        elif '\r' in outp:
            # Horribly inefficient due to lack of an inbuilt function to get client IP
            # Not to mention possibly inaccurate for multiple connections... someone help me out here
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

            # Log the attempt in a CSV file because I love spreadsheets
            with open("attempts.csv", 'a', newline='') as attempt:
                outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
                outfile.writerow([current_time, username, client_ip, ip_country, ip_region, ip_city, ip_isp])

            writer.write(message) # Inform user that they've been caught
            break
        else:
            username += outp
            writer.write(outp)
    writer.close()

# Create a new CSV log file if it doesn't exist already
if not path.exists("attempts.csv"):
    with open("attempts.csv", 'w', newline='') as atts:
        initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
        initial.writerow(["Time", "Username", "IP", "Country", "Region", "City", "ISP"])

loop = asyncio.get_event_loop()
coro = telnetlib3.create_server(port=listen_port, shell=honeypot, timeout=20)
print("Simple Telnet Honeypot running!")
telnet_server = loop.run_until_complete(coro)
loop.run_until_complete(telnet_server.wait_closed())