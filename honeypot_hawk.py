from multiprocessing import Process
import telnet
import ssh
import port_scan

def start_telnet():
    telnet_thread = Process(target=telnet.run_telnet)
    telnet_thread.start()

def start_ssh():
    ssh_thread = Process(target=ssh.run_ssh)
    ssh_thread.start()

def start_port_scan():
    port_scan_thread = Process(target=port_scan.run_port_scan)
    port_scan_thread.start()

if __name__ == '__main__':
    print("Starting...")
    start_telnet()
    start_ssh()
    start_port_scan()
