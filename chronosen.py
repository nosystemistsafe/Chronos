print("""
   █████████  █████   █████ ███████████      ███████    ██████   █████    ███████     █████████ 
  ███░░░░░███░░███   ░░███ ░░███░░░░░███   ███░░░░░███ ░░██████ ░░███   ███░░░░░███  ███░░░░░███
 ███     ░░░  ░███    ░███  ░███    ░███  ███     ░░███ ░███░███ ░███  ███     ░░███░███    ░░░ 
░███          ░███████████  ░██████████  ░███      ░███ ░███░░███░███ ░███      ░███░░█████████ 
░███          ░███░░░░░███  ░███░░░░░███ ░███      ░███ ░███ ░░██████ ░███      ░███ ░░░░░░░░███
░░███     ███ ░███    ░███  ░███    ░███ ░░███     ███  ░███  ░░█████ ░░███     ███  ███    ░███
 ░░█████████  █████   █████ █████   █████ ░░░███████░   █████  ░░█████ ░░░███████░  ░░█████████ 
  ░░░░░░░░░  ░░░░░   ░░░░░ ░░░░░   ░░░░░    ░░░░░░░    ░░░░░    ░░░░░    ░░░░░░░     ░░░░░░░░░  
""")
print("""Chronos is made by tunaeymen027. A Turkish white hat hacker and ethical cyber security program maker. He is not the responsible
of what you do with this program.""")
print("""Chronos is an IP mapper, Proxy, UDP port, and Port scanner.""")
print("""Chronos v1.0""")

import socket
import requests
from concurrent.futures import ThreadPoolExecutor

def get_ip_properties(ip):
    ip_properties = {
        "IP Address": ip,
        "IP Version": "IPv4" if ":" not in ip else "IPv6",
    }

    try:
        hostname = socket.gethostbyaddr(ip)
        ip_properties["DNS Name"] = hostname[0]
    except socket.herror:
        ip_properties["DNS Name"] = "No_DNS_Entry"

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            ip_properties["System Name"] = data.get("hostname", "Not Available")
            ip_properties["Network Interface Name"] = data.get("org", "Not Available")
            ip_properties["Location"] = data.get("loc", "Not Available")
        else:
            print(f"Error retrieving data from IPinfo: {response.status_code}")
    except Exception as e:
        print(f"Error: {e}")

    return ip_properties

def scan_tcp_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((ip, port))
            return port, True
        except (socket.timeout, ConnectionRefusedError):
            return port, False

def scan_udp_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(1)
        try:
            s.sendto(b'', (ip, port))
            s.recvfrom(1024)
            return port, True
        except socket.timeout:
            return port, False

def scan_ports(ip, start_port, end_port, turbo, protocol='tcp'):
    scan_function = scan_tcp_port if protocol == 'tcp' else scan_udp_port
    with ThreadPoolExecutor(max_workers=turbo) as executor:
        results = executor.map(lambda p: scan_function(ip, p), range(start_port, end_port + 1))
    return {port: status for port, status in results}

def scan_proxy_ports(ip, proxy_ports, turbo, protocol='tcp'):
    with ThreadPoolExecutor(max_workers=turbo) as executor:
        results = executor.map(lambda p: scan_tcp_port(ip, p) if protocol == 'tcp' else scan_udp_port(ip, p), proxy_ports)
    return {port: status for port, status in results}

server = input("Please enter the Server IP or URL: ")
port = int(input("Please enter the Port (default is 80): ") or 80)
start_port = int(input("Enter the starting port for scan (default is 1): ") or 1)
end_port = int(input("Enter the ending port for scan (default is 1024): ") or 1024)
turbo = int(input("Enter the Turbo level (default is 10): ") or 10)
silent_mode = input("Enable silent mode? (y/n): ").strip().lower() == 'y'
protocol = input("Choose the protocol to scan (tcp/udp): ").strip().lower() or 'tcp'

if not silent_mode:
    print(f"\n[Server IP/URL: {server}]  [Port: {port}]  [Turbo: {turbo}]  [Protocol: {protocol}]\n")
    print("Fetching IP properties...\n")

ip_properties = get_ip_properties(server)
if not silent_mode:
    for key, value in ip_properties.items():
        print(f"{key}: {value}")

if not silent_mode:
    print(f"\nScanning ports {start_port}-{end_port}...\n")

found_open_port = False

scan_results = scan_ports(server, start_port, end_port, turbo, protocol)

normal_scan_results = {port: status for port, status in scan_results.items()}

proxy_ports = [8080, 3128, 8888, 1080, 8000]
if not silent_mode:
    print(f"\nScanning proxy ports {proxy_ports}...\n")

proxy_scan_results = scan_proxy_ports(server, proxy_ports, turbo, protocol)

all_results = {**normal_scan_results, **proxy_scan_results}

if not silent_mode:
    print("\nPort scan results:")
    for port, is_open in all_results.items():
        if is_open:
            print(f"Port {port}: OPEN")
        else:
            print(f"Port {port}: CLOSED")
