import socket
import requests
from concurrent.futures import ThreadPoolExecutor

def get_ip_properties(ip):
    ip_properties = {
        "IP-адрес": ip,
        "IP-версия": "IPv4" if ":" not in ip else "IPv6",
    }

    try:
        hostname = socket.gethostbyaddr(ip)
        ip_properties["DNS-имя"] = hostname[0]
    except socket.herror:
        ip_properties["DNS-имя"] = "Нет записи DNS"

    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            ip_properties["Имя системы"] = data.get("hostname", "Недоступно")
            ip_properties["Имя сетевого интерфейса"] = data.get("org", "Недоступно")
            ip_properties["Местоположение"] = data.get("loc", "Недоступно")
        else:
            print(f"Ошибка при получении данных от IPinfo: {response.status_code}")
    except Exception as e:
        print(f"Ошибка: {e}")

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

server = input("Введите IP-адрес сервера или URL: ")
port = int(input("Введите порт (по умолчанию 80): ") or 80)
start_port = int(input("Введите начальный порт для сканирования (по умолчанию 1): ") or 1)
end_port = int(input("Введите конечный порт для сканирования (по умолчанию 1024): ") or 1024)
turbo = int(input("Введите уровень Turbo (по умолчанию 10): ") or 10)
silent_mode = input("Включить тихий режим? (д/н): ").strip().lower() == 'д'
protocol = input("Выберите протокол для сканирования (tcp/udp): ").strip().lower() or 'tcp'

if not silent_mode:
    print(f"\n[IP/URL сервера: {server}]  [Порт: {port}]  [Turbo: {turbo}]  [Протокол: {protocol}]\n")
    print("Получение свойств IP...\n")

ip_properties = get_ip_properties(server)
if not silent_mode:
    for key, value in ip_properties.items():
        print(f"{key}: {value}")

if not silent_mode:
    print(f"\nСканирование портов {start_port}-{end_port}...\n")

found_open_port = False

scan_results = scan_ports(server, start_port, end_port, turbo, protocol)

normal_scan_results = {port: status for port, status in scan_results.items()}

proxy_ports = [8080, 3128, 8888, 1080, 8000]
if not silent_mode:
    print(f"\nСканирование прокси-портов {proxy_ports}...\n")

proxy_scan_results = scan_proxy_ports(server, proxy_ports, turbo, protocol)

all_results = {**normal_scan_results, **proxy_scan_results}

if not silent_mode:
    print("\nРезультаты сканирования портов:")
    for port, is_open in all_results.items():
        if is_open:
            print(f"Порт {port}: ОТКРЫТ")
        else:
            print(f"Порт {port}: ЗАКРЫТ")
