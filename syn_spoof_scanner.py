import argparse
import random
import ipaddress
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import get_if_hwaddr, Ether, conf
import socket
import threading
from queue import Queue
from colorama import Fore, Style, init

# Initialize colorama for cross-platform support
init()

def display_banner():
    banner = f"""
{Fore.CYAN}
  ______   ___   _   ____                     __   ____
 / ___\ \ / / \ | | / ___| _ __   ___   ___  / _| / ___|  ___ __ _ _ __  _ __   ___ _ __
 \___ \\\\ V /|  \| | \___ \| '_ \ / _ \ / _ \| |_  \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
  ___) || | | |\  |  ___) | |_) | (_) | (_) |  _|  ___) | (_| (_| | | | | | | |  __/ |
 |____/ |_| |_| \_| |____/| .__/ \___/ \___/|_|   |____/ \___\__,_|_| |_|_| |_|\___|_|
                          |_|
{Style.RESET_ALL}
                                                            By: Tier Zero Security - NZ
    """
    print(banner)

def determine_host_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print(f"{Fore.RED}Error determining host IP: {e}{Style.RESET_ALL}")
        return "127.0.0.1"

def syn_scan(target, ports, source_ip, source_mac, iface, open_only=False, output_queue=None):
    result = []
    result.append(f"{Fore.YELLOW}Starting SYN scan on {target}{Style.RESET_ALL}")
    result.append("-" * 40)
    result.append(f"PORT     STATE       RESPONSE")

    for port in ports:
        pkt = Ether(src=source_mac) / IP(src=source_ip, dst=target) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        response = srp1(pkt, iface=iface, timeout=1, verbose=0)

        if response and TCP in response and response[TCP].flags == "SA":
            if not open_only:
                result.append(f"{Fore.GREEN}{port:<7} open       SYN-ACK received{Style.RESET_ALL}")
            else:
                result.append(f"{Fore.GREEN}{port:<7} open{Style.RESET_ALL}")
        elif not open_only:
            result.append(f"{port:<7} closed     No response")

    if not open_only:
        result.append("-" * 40)

    if output_queue:
        output_queue.put(result)

def perform_spoofed_scan(spoofed_ips_and_macs, target, ports, default_source_mac, iface, output_queue=None):
    random.shuffle(spoofed_ips_and_macs)

    threads = []
    for spoofed_ip, spoofed_mac in spoofed_ips_and_macs:
        thread = threading.Thread(
            target=send_spoofed_packets,
            args=(spoofed_ip, target, ports, spoofed_mac or default_source_mac, iface)
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return spoofed_ips_and_macs

def send_spoofed_packets(spoofed_ip, target, ports, source_mac, iface):
    for port in ports:
        mac_to_use = source_mac if source_mac else get_if_hwaddr(iface)
        pkt = Ether(src=mac_to_use) / IP(src=spoofed_ip, dst=target) / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        sendp(pkt, iface=iface, verbose=0)

def load_spoofed_ips(file_path):
    spoofed_ips_and_macs = []
    with open(file_path, "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:  # Expecting "IP,MAC" format
                spoofed_ips_and_macs.append((parts[0], parts[1]))
            elif len(parts) == 1:  # IP only
                spoofed_ips_and_macs.append((parts[0], None))
    return spoofed_ips_and_macs

def main():
    display_banner()

    parser = argparse.ArgumentParser(description="SYN Scan Tool with Optional Spoofed IPs, Multithreading, and Modes")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or comma-separated IPs/subnets")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports to scan")
    parser.add_argument("-F", "--fast", action="store_true", help="Perform a scan of the top 100 common ports (like Nmap)")
    parser.add_argument("-s", "--source-ip", help="Source IP address to use for scanning")
    parser.add_argument("-i", "--interface", help="Network interface to use for sending packets (e.g., eth0, wlan0)")
    parser.add_argument("-ss", "--spoofed-ips", help="Comma-separated list of spoofed source IPs")
    parser.add_argument("-f", "--file", help="File containing spoofed IPs (one per line)")
    parser.add_argument("--open", action="store_true", help="Only display open ports")

    args = parser.parse_args()

    top_100_ports = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
                     143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
                     631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
                     1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
                     5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008,
                     8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157]

    if args.fast:
        ports = top_100_ports
    elif args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print(f"{Fore.RED}Error: Ports must be integers. Use a comma-separated list (e.g., 80,443,22).{Style.RESET_ALL}")
            return
    else:
        print(f"{Fore.RED}Error: Specify ports with -p or use -F for a fast scan{Style.RESET_ALL}")
        return

    iface = args.interface or conf.iface
    source_mac = get_if_hwaddr(iface)
    source_ip = args.source_ip

    if args.file:
        spoofed_ips_and_macs = load_spoofed_ips(args.file)
    elif args.spoofed_ips:
        spoofed_ips_and_macs = [(ip.strip(), None) for ip in args.spoofed_ips.split(",")]
    else:
        spoofed_ips_and_macs = []

    targets = []
    for entry in args.target.split(","):
        try:
            network = ipaddress.ip_network(entry.strip(), strict=False)
            targets.extend([str(ip) for ip in network.hosts()])
        except ValueError:
            targets.append(entry.strip())

    if not targets:
        print(f"{Fore.RED}Error: No valid targets specified. Ensure the --target parameter includes valid IPs or subnets.{Style.RESET_ALL}")
        return

    output_queue = Queue()
    scan_threads = []
    if source_ip:
        print(f"{Fore.YELLOW}Performing SYN port scan using:{Style.RESET_ALL}")
        print(f" - Source IP: {source_ip}")
        print(f" - Source MAC: {source_mac}")
        print("-" * 40)
        for target in targets:
            main_scan_thread = threading.Thread(
                target=syn_scan, args=(target, ports, source_ip, source_mac, iface, args.open, output_queue)
            )
            scan_threads.append(main_scan_thread)
            main_scan_thread.start()
    else:
        print(f"{Fore.YELLOW}No source IP (-s) provided. Only performing SYN spoof scans{Style.RESET_ALL}")
        target_list = ", ".join(map(str, targets))
        print(f"{Fore.YELLOW}Target IPs:{Style.RESET_ALL}\n - {target_list}")
    if spoofed_ips_and_macs:
        spoofed_used = perform_spoofed_scan(
            spoofed_ips_and_macs, targets[0], ports, source_mac, iface, output_queue
        )

    for thread in scan_threads:
        thread.join()

    while not output_queue.empty():
        output = output_queue.get()
        for line in output:
            print(line)

    if spoofed_ips_and_macs:
        print(f"\n{Fore.YELLOW}Spoofed IPs and MACs used:{Style.RESET_ALL}")
        for ip, mac in spoofed_used:
            mac_display = mac if mac else "Default MAC"
            print(f" - {ip} (MAC: {mac_display})")

if __name__ == "__main__":
    main()

