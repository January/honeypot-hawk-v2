from multiprocessing import Process
import datetime
import telnet
import ssh
import port_scan
import ftp
import smb
import requests
import sys
import os
import time

class HoneypotHawk:
    telnet_thread = Process(target=telnet.run_honeypot, daemon=True)

    ssh_thread = Process(target=ssh.run_honeypot, daemon=True)

    port_scan_thread = Process(target=port_scan.run_honeypot, daemon=True)

    ftp_thread = Process(target=ftp.run_honeypot, daemon=True)

    smb_thread = Process(target=smb.run_honeypot, daemon=True)

    # These are necessary workarounds since you (still) can't start a process twice.
    def start_telnet(self):
        if not self.telnet_thread.is_alive():
            try:
                self.telnet_thread.start()
            except AssertionError:
                self.telnet_thread = Process(target=telnet.run_honeypot, daemon=True)
                self.telnet_thread.start()

    def start_ssh(self):
        if not self.ssh_thread.is_alive():
            try:
                self.ssh_thread.start()
            except AssertionError:
                self.ssh_thread = Process(target=ssh.run_honeypot, daemon=True)
                self.ssh_thread.start()

    def start_port_scan(self):
        if not self.port_scan_thread.is_alive():
            try:
                self.port_scan_thread.start()
            except AssertionError:
                self.port_scan_thread = Process(target=port_scan.run_honeypot, daemon=True)
                self.port_scan_thread.start()

    def start_ftp(self):
        if not self.ftp_thread.is_alive():
            try:
                self.ftp_thread.start()
            except AssertionError:
                self.ftp_thread = Process(target=ftp.run_honeypot, daemon=True)
                self.ftp_thread.start()

    def start_smb(self):
        if not self.smb_thread.is_alive():
            try:
                self.smb_thread.start()
            except AssertionError:
                self.smb_thread = Process(target=smb.run_honeypot, daemon=True)
                self.smb_thread.start()

    def stop_telnet(self):
        if self.telnet_thread.is_alive():
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[Telnet @ {end_time}] Stopping telnet honeypot.")
            self.telnet_thread.terminate()

    def stop_ssh(self):
        if self.ssh_thread.is_alive():
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[SSH @ {end_time}] Stopping SSH honeypot.")
            self.ssh_thread.terminate()

    def stop_port_scan(self):
        if self.port_scan_thread.is_alive():
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[Port-scan @ {end_time}] Stopping port scan honeypot.")
            self.port_scan_thread.terminate()

    def stop_ftp(self):
        if self.ftp_thread.is_alive():
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[FTP @ {end_time}] Stopping FTP honeypot.")
            self.ftp_thread.terminate()

    def stop_smb(self):
        if self.smb_thread.is_alive():
            end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[SMB @ {end_time}] Stopping SMB honeypot.")
            self.smb_thread.terminate()

    def start_all(self):
        self.start_telnet()
        self.start_ssh()
        self.start_port_scan()
        self.start_ftp()
        self.start_smb()

    def stop_all(self):
        self.stop_telnet()
        self.stop_ssh()
        self.stop_port_scan()
        self.stop_ftp()
        self.stop_smb()

    def restart_all(self):
        self.stop_all()
        time.sleep(1)
        self.start_all()

    def start(self):
        ip_api = requests.get(f"http://ip-api.com/json/").json()
        ip = ip_api['query']
        region_name = ip_api['regionName']
        country_name = ip_api['country']
        start_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{start_time}] Starting Honeypot Hawk on {ip} ({region_name}, {country_name})")
        print("To start a certain honeypot, enter its number. To stop it, just enter its number again. Options:")
        print("[1] Telnet honeypot")
        print("[2] SSH honeypot")
        print("[3] Port scan honeypot")
        print("[4] FTP honeypot")
        print("[5] SMB honeypot")
        print("-------------------------")
        print("[6] Start all honeypots")
        print("[7] Stop all honeypots")
        print("[8] Restart all honeypots")
        print("[9] Quit Honeypot Hawk (kills all honeypots)")
        print("Please make your choice now: ", end="")
        while True:
            try:
                selection = int(input())
                if selection == 1:
                    if not self.telnet_thread.is_alive():
                        self.start_telnet()
                    else:
                        self.stop_telnet()
                elif selection == 2:
                    if not self.ssh_thread.is_alive():
                        self.start_ssh()
                    else:
                        self.stop_ssh()
                elif selection == 3:
                    if not self.port_scan_thread.is_alive():
                        self.start_port_scan()
                    else:
                        self.stop_port_scan()
                elif selection == 4:
                    if not self.ftp_thread.is_alive():
                        self.start_ftp()
                    else:
                        self.stop_ftp()
                elif selection == 5:
                    if not self.smb_thread.is_alive():
                        self.start_smb()
                    else:
                        self.stop_smb()
                elif selection == 6:
                    self.start_all()
                elif selection == 7:
                    self.stop_all()
                elif selection == 8:
                    self.restart_all()
                elif selection == 9:
                    self.stop_all()
                    end_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    print(f"[{end_time}] Exiting Honeypot Hawk, see you next time.")
                    try:
                        sys.exit(0)
                    except SystemExit:
                        os._exit(0)
                else:
                    print("Not a valid choice.")
            except ValueError:
                print("Not a valid choice.")
                continue

if __name__ == '__main__':
    h = HoneypotHawk()
    h.start()