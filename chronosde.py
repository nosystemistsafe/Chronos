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
print("""Dieses Programm muss nicht überprüft werden, da Sie dieses Programm löschen möchten."")
print(""Chronos – ein IP-Server, ein Proxy-Server, ein UDP-Port und ein Scan-Port.""")
print("""Chronos v1.0""")

import socket
import requests
from concurrent.futures import ThreadPoolExecutor

def get_ip_properties(ip):
    ip_properties = {
        "IP-Adresse": ip,
        "IP-Version": "IPv4" if ":" not in ip else "IPv6",
    }

    try:
        hostname = socket.gethostbyaddr(ip)
        ip_properties["DNS-Name"] = hostname[0]
    except socket.herror:
        ip_properties["DNS-Name"] = "No_DNS_Entry"

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            ip_properties["System-Name"] = data.get("hostname", "Nicht verfügbar")
            ip_properties["Netzwerkschnittstellen-Name"] = data.get("org", "Nicht verfügbar")
            ip_properties["Standort"] = data.get("loc", "Nicht verfügbar")
        else:
            print(f"Fehler beim Abrufen der Daten von IPinfo: {response.status_code}")
    except Exception as e:
        print(f"Fehler: {e}")

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

server = input("Bitte geben Sie die Server-IP oder URL ein: ")
port = int(input("Bitte geben Sie den Port ein (Standard ist 80): ") or 80)
start_port = int(input("Geben Sie den Startport für den Scan ein (Standard ist 1): ") or 1)
end_port = int(input("Geben Sie den Endport für den Scan ein (Standard ist 1024): ") or 1024)
turbo = int(input("Geben Sie das Turbo-Level ein (Standard ist 10): ") or 10)
silent_mode = input("Möchten Sie den Stillen Modus aktivieren? (j/n): ").strip().lower() == 'j'
protocol = input("Wählen Sie das Protokoll für den Scan (tcp/udp): ").strip().lower() or 'tcp'

if not silent_mode:
    print(f"\n[Server-IP/URL: {server}]  [Port: {port}]  [Turbo: {turbo}]  [Protokoll: {protocol}]\n")
    print("IP-Eigenschaften werden abgerufen...\n")

ip_properties = get_ip_properties(server)
if not silent_mode:
    for key, value in ip_properties.items():
        print(f"{key}: {value}")

if not silent_mode:
    print(f"\nPorts {start_port}-{end_port} werden gescannt...\n")

found_open_port = False

scan_results = scan_ports(server, start_port, end_port, turbo, protocol)

normal_scan_results = {port: status for port, status in scan_results.items()}

proxy_ports = [8080, 3128, 8888, 1080, 8000]
if not silent_mode:
    print(f"\nProxy-Ports {proxy_ports} werden gescannt...\n")

proxy_scan_results = scan_proxy_ports(server, proxy_ports, turbo, protocol)

all_results = {**normal_scan_results, **proxy_scan_results}

if not silent_mode:
    print("\nPort-Scan-Ergebnisse:")
    for port, is_open in all_results.items():
        if is_open:
            print(f"Port {port}: OFFEN")
        else:
            print(f"Port {port}: GESCHLOSSEN")
