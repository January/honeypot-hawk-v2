import socketserver
import logging
import struct
import time
import socket  # Needed to catch socket.timeout
import yaml
import datetime
from dateutil.parser import isoparse
import requests
import csv
import os
import json

# Load yaml config
config = yaml.safe_load(open("config.yml"))

# CSV log name
csv_outfile = config['smb_csv_name']

# Load port from config file
port = config['smb_port']

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

# This is the worst thing
def parse_smb_message(data: bytes):
    # At a minimum we need 4 bytes.
    if len(data) < 4:
        return None

    offset = 0
    netbios = False

    # Check if we're just on SMB1...
    if data[0:4] in (b'\xffSMB', b'\xfeSMB'):
        sig = data[0:4]
        offset = 0
    # ...or NetBIOS + SMB.
    elif len(data) >= 8 and data[4:8] in (b'\xffSMB', b'\xfeSMB'):
        sig = data[4:8]
        offset = 4
        netbios = True
    else:
        return None

    if sig == b'\xffSMB':
        # SMB1
        if len(data) < offset + 32:
            return None

        smb_header = data[offset:offset+32]
        if smb_header[0:4] != b'\xffSMB':
            return None

        # In SMB1, the command is the 5th byte.
        command = smb_header[4]
        if command != 0x72:
            return None

        if len(data) < offset + 35:
            return None

        # Word count, but should be zero
        word_count = data[offset+32]
        byte_count = struct.unpack("<H", data[offset+33:offset+35])[0]
        if len(data) < offset + 35 + byte_count:
            return None

        dialects_data = data[offset+35: offset+35+byte_count]
        dialects = []
        dialect_offset = 0

        # Dialects can be literally anything in SMB1 lol
        while dialect_offset < len(dialects_data):
            if dialects_data[dialect_offset] != 0x02:
                dialect_offset += 1
                continue
            dialect_offset += 1  # Skip the dialect indicator.
            end = dialects_data.find(b'\x00', dialect_offset)
            if end == -1:
                break  # No terminating null found.
            try:
                dialect = dialects_data[dialect_offset:end].decode('ascii', errors='replace')
            except Exception:
                dialect = dialects_data[dialect_offset:end].hex()
            dialects.append(dialect)
            dialect_offset = end + 1

        return {
            'dialects': dialects,
            'type': "NetBIOS + SMB1" if netbios else "SMB1"
        }

    elif sig == b'\xfeSMB':
        # SMB2/3
        if len(data) < offset + 64:
            return None

        smb2_header = data[offset:offset+64]
        if smb2_header[0:4] != b'\xfeSMB':
            return None

        # Negotiate field, should be 0
        command = struct.unpack("<H", data[offset+12:offset+14])[0]
        if command != 0x0000:
            return None

        # Negotiate request body
        body_offset = offset + 64
        if len(data) < body_offset + 36:
            return None

        # Structure size (should be 36)
        structure_size = struct.unpack("<H", data[body_offset:body_offset+2])[0]
        if structure_size != 36:
            return None

        # Dialect count
        dialect_count = struct.unpack("<H", data[body_offset+2:body_offset+4])[0]
        expected_body_len = 36 + 2 * dialect_count
        if len(data) < body_offset + expected_body_len:
            return None

        dialects = []
        # As far as I know this is all possible dialects
        smb2_dialect_map = {
            0x0202: "SMB 2.0.2",
            0x0210: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0302: "SMB 3.0.2",
            0x0311: "SMB 3.1.1"
        }
        for i in range(dialect_count):
            start = body_offset + 36 + 2*i
            dial_val = struct.unpack("<H", data[start:start+2])[0]
            dialect_str = smb2_dialect_map.get(dial_val, "0x%04x" % dial_val)
            dialects.append(dialect_str)

        return {
            'dialects': dialects,
            'type': "NetBIOS + SMB2/3" if netbios else "SMB2/3"
        }
    else:
        return None

class Honeypot(socketserver.BaseRequestHandler):
    def handle(self):
        client_ip, client_port = self.client_address
        start_time = time.time()
        data_buffer = b""
        # Automatically disconnect inactive or invalid connections
        while True:
            elapsed = time.time() - start_time
            if elapsed >= 30:
                # Someone connected but didn't send a SMB message for 30s, disconnect them
                break

            remaining_time = 30 - elapsed
            try:
                self.request.settimeout(remaining_time)
                data = self.request.recv(4096)
            except socket.timeout:
                break

            if not data:
                # Client closed the connection for some reason
                break

            data_buffer += data
            parsed = parse_smb_message(data_buffer)
            if parsed is not None:
                logging.info("Valid SMB header received. Dialects: %s, Type: %s", parsed.get('dialects'), parsed.get('type'))
                smb_type = parsed.get('type')
                smb_dialects = ", ".join(parsed.get('dialects'))
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
                current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                # Log the attempt in console if enabled
                if config['console_logging']:
                    print(f"[SMB @ {current_time}] {client_ip} ({ip_city}, {ip_region}, {ip_country}) triggered honeypot. Type: {smb_type}. Dialect(s): {smb_dialects}")
                # Log attempt in CSV if enabled
                if config['csv_logging']:
                    with open(csv_outfile, 'a', newline='') as attempt:
                        outfile = csv.writer(attempt, quoting=csv.QUOTE_MINIMAL)
                        outfile.writerow([current_time, client_ip,
                                        ip_country, ip_region, ip_city, ip_isp])
                # Report attempt to AbuseIPDB if enabled
                if config['abuseipdb_enable']:
                    if not ip_in_list(client_ip): # Check if this IP is in the last n that were reported
                        if not check_reports(client_ip):
                            ip_list.append({"ip": client_ip, "timestamp": time.time()})
                            utc_time = datetime.datetime.utcnow().strftime("%H:%M")
                            report_data = {"ip": client_ip, "categories": "18", "comment": f"[{utc_time}] Triggered SMB honeypot on port {port}. Type: {smb_type}. Dialect(s): {smb_dialects}", "key": config['abuseipdb_key']}
                            repost = requests.post(abipdb_endpoint, json=report_data)
                            if "errors" in json.loads(repost.text):
                                log_failed_report(report_data)
                break

def run_honeypot():
    try:
        with socketserver.ThreadingTCPServer(("", port), Honeypot) as server:
            start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[SMB @ {start_time}] SMB honeypot running!")
            server.serve_forever()
    except Exception as e:
        print(f"Failed to start SMB honeypot: {e}")