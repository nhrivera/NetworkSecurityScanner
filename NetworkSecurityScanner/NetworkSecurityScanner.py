from site import ENABLE_USER_SITE
from tkinter import END
from scapy.all import ARP, Ether, srp
import socket
import requests

def scan_network(target_ip):
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients
    
network_range = "192.168.0.1/24"
devices = scan_network(network_range)  

print("Devices found:")
for device in devices:
    print(f"IP Address: {device['ip']}, MAC Address: {device['mac']}")


def check_open_ports(ip, port_range):
    open_ports = []
    for port in port_range:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
                
    return open_ports

ip_address = input("Please input IP from any listed above: ")
ports_to_scan = range(1,1025)
open_ports = check_open_ports(ip_address, ports_to_scan)

print(f"Open ports on {ip_address}: {open_ports}")

def get_vulnerabilities(service_name):
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=port {service_name}&keywordExactMatch"
    response = requests.get(api_url)
    if response.status_code == 200:
        return response.json()
    else:
        return None
service = input("Please input a port number from any listed above: ")
vulnerabilities = get_vulnerabilities(service)

if vulnerabilities:
    print(f"Current number of Vulnerabilities documented for port {service} on nist.gov: ")
    for k, v in vulnerabilities.items():
        if k == "totalResults":
            print(v)
else:
    print(f"No vulnerabilities found or unable to check for port {service} on nist.gov")