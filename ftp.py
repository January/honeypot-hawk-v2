from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import csv
import datetime
from dateutil.parser import isoparse
import json
import os
import requests
import socket
import time
import yaml
import sys
from pyftpdlib.log import config_logging
import logging

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# CSV log name
csv_outfile = config['ftp_csv_name']

# Load port from config file
port = config['ftp_port']

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

class Honeypot(FTPHandler):
    def on_login_failed(self, username, password):
        """ Log all login attempts and reject access. """
        self.ip_country = "Unknown"
        self.ip_region = "Unknown"
        self.ip_city = "Unknown"
        self.ip_isp = "Unknown"

        # Gather location data using IP-API
        url = f"http://ip-api.com/json/{self.remote_ip}"
        resp = requests.get(url=url).json()
        if(resp['status'] == 'success'):
            self.ip_country = resp['country']
            self.ip_region = resp['regionName']
            self.ip_city = resp['city']
            self.ip_isp = resp['isp']
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Log the attempt in console if enabled
        if config['console_logging']:
            print(f"[FTP @ {current_time}] {self.remote_ip} ({self.ip_city}, {self.ip_region}, {self.ip_country}) tried logging in with {username}:{password}")
        # Log attempt in CSV if enabled
        if config['csv_logging']:
            with open(csv_outfile, 'a', newline='') as attempt:
                outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
                outfile.writerow([current_time, username, password, self.remote_ip,
                                  self.ip_country, self.ip_region, self.ip_city, self.ip_isp])
        # Report attempt to AbuseIPDB if enabled
        if config['abuseipdb_enable']:
            if not ip_in_list(self.remote_ip): # Check if this IP is in the last n that were reported
                if not check_reports(self.remote_ip):
                    ip_list.append({"ip": self.remote_ip, "timestamp": time.time()})
                    utc_time = datetime.datetime.utcnow().strftime("%H:%M")
                    report_data = {"ip": self.remote_ip, "categories": "5,18", "comment": f"[{utc_time}] Attempted FTP login on port {port} with credentials {username}:{password}", "key": config['abuseipdb_key']}
                    repost = requests.post(abipdb_endpoint, json=report_data)
                    if "errors" in json.loads(repost.text):
                        log_failed_report(report_data)

def run_honeypot():
    config_logging(level=logging.ERROR) # Don't spam our console.
    authorizer = DummyAuthorizer()  # This way, no username or password will ever be accepted.
    handler = Honeypot
    handler.authorizer = authorizer

    server = FTPServer(("0.0.0.0", port), handler)
    start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[FTP @ {start_time}] FTP honeypot running!")
    server.serve_forever()