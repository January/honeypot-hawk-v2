import csv
from Crypto.PublicKey import RSA
import datetime
import os
import requests
import socket
import sys
import threading
import _thread
import paramiko
import yaml

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# Generate keys if they don't exist
if not os.path.exists("server.key"):
    key = RSA.generate(3072)
    with open("server.key", 'wb') as content_file:
        content_file.write(key.exportKey('PEM'))
if not os.path.exists("server.pub"):
    pubkey = key.publickey()
    with open("server.pub", 'wb') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))
server_key = paramiko.RSAKey(filename='server.key')

# Port the SSH server will listen on.
port = config['ssh_port']

# CSV log name
csv_outfile = config['ssh_csv_name']

# AbuseIPDB endpoint
abipdb_endpoint = "https://api.abuseipdb.com/api/v2/report"

# List of recently caught IPs, meant to avoid duplicate reports on AbuseIPDB
# as to not exhaust the daily report allowance early because of duplicates
ip_list = []

class Honeypot(paramiko.ServerInterface):
    def __init__(self, connection):
        self.event = threading.Event()
        self.connection = connection
        self.ip_country = "Unknown"
        self.ip_region = "Unknown"
        self.ip_city = "Unknown"
        self.ip_isp = "Unknown"

        # Gather location data using IP-API
        url = f"http://ip-api.com/json/{connection}"
        resp = requests.get(url=url).json()
        if(resp['status'] == 'success'):
            self.ip_country = resp['country']
            self.ip_region = resp['regionName']
            self.ip_city = resp['city']
            self.ip_isp = resp['isp']

    def check_auth_password(self, username, password):
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Log the attempt in console if enabled
        if config['console_logging']:
            print(f"[SSH @ {current_time}] {self.connection} ({self.ip_city}, {self.ip_region}, {self.ip_country}) tried logging in with {username}:{password}")
        # Log attempt in CSV if enabled
        if config['csv_logging']:
            with open(csv_outfile, 'a', newline='') as attempt:
                outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
                outfile.writerow([current_time, username, password, self.connection,
                                  self.ip_country, self.ip_region, self.ip_city, self.ip_isp])
        # Report attempt to AbuseIPDB if enabled
        if config['abuseipdb_enable']:
            if self.connection not in ip_list: # Check if this IP is in the last n that were reported
                if len(ip_list) == config['ip_log']:
                    ip_list.pop(0)
                ip_list.append(self.connection)
                report_data = {"ip": self.connection, "categories": "18,22", "comment": f"Attempted SSH login on port {port} with credentials {username}:{password}", "key": config['abuseipdb_key']}
                requests.post(abipdb_endpoint, json=report_data)
        # Always fail.
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

def handleConnection(client):
    try:
        transport = paramiko.Transport(client)
        transport.add_server_key(server_key)

        ip = transport.getpeername()[0]

        transport.start_server(server=Honeypot(ip))

        channel = transport.accept(1)
        if not channel is None:
            channel.close()
    # These errors aren't super important but spam the logs if not handled
    except paramiko.SSHException:
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[SSH @ {current_time}] Connection error from {ip}. Ignoring.")

def run_honeypot():
    # Create a new CSV log file if it's enabled and doesn't exist already
    if config['csv_logging'] and not os.path.exists(csv_outfile):
        with open(csv_outfile, 'w', newline='') as atts:
            initial = csv.writer(atts, quoting=csv.QUOTE_MINIMAL)
            initial.writerow(["Time", "Username", "Password", "IP", "Country", "Region", "City", "ISP"])

    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[SSH @ {start_time}] SSH honeypot running!")

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', port))
        server_socket.listen(100)
        while True:
            try:
                client_socket, client_addr = server_socket.accept()
                _thread.start_new_thread(handleConnection,(client_socket,))
            except KeyboardInterrupt:
                end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[SSH @ {end_time}] Stopping SSH honeypot.")
                try:
                    sys.exit(129)
                except SystemExit:
                    os._exit(129)
    except Exception as e:
        print("Error: Couldn't create socket.")
        print(e)
        sys.exit(1)