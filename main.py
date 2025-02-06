from ipaddress import ip_address
import argparse
import socket
import subprocess
import re

from netaddr.ip.rfc1924 import BASE_85_DICT
from scapy.all import *
from netaddr import IPNetwork, IPRange  # Ensure netaddr is installed
from tokenize import String

# Function to detect local subnet (if no target is provided)
def get_local_subnet():
    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True)

        for line in result.stdout.split("\n"):
            if "src" in line:
                match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    local_ip = match.group(1)
                    subnet = local_ip.rsplit(".", 1)[0] + ".0/24"
                    print(f"[*] No target specified. Scanning local subnet: {subnet}")
                    return subnet

        print("[!] Could not detect local network, using fallback method.")
        fallback_ip = socket.gethostbyname(socket.gethostname())
        subnet = fallback_ip.rsplit(".", 1)[0] + ".0/24"
        return subnet

    except Exception as e:
        print(f"[!] Failed to detect local subnet: {e}")
        return "192.168.0.0/24"  # Default if detection fails

# Function to check if a host is online using ARP
def is_host_online(target):
    """
    Uses ARP to check if a target is online.
    Loopback addresses (127.x.x.x) are always considered reachable.
    """
    if target.startswith("127."):
        return True

    ans, _ = arping(target, timeout=1, verbose=False)
    return len(ans) > 0


def syn_scan(target, port):
    """
    Sends a SYN packet and analyzes the response.

    :param target: Target IP address
    :param port: Target Port
    :return: String indicating the status of the port
    """
    ip_layer = IP(dst=target)
    tcp_layer = TCP(dport=port, flags="S")
    packet = ip_layer/tcp_layer
    syn_ack = sr1(packet)
    print(syn_ack)
    if syn_ack:
        if syn_ack.haslayer(TCP):
            if syn_ack.getlayer(TCP).flags == 0x12: # This is 00010010 in binary
                print(f"{port} is OPEN")
                return "open"
            elif syn_ack.getlayer(TCP).flags == 0x14: # This is 00010100 in binary
                print(f"{port} is CLOSED")
                return "closed"
        else:
            print(f"{port} is FILTERED")
            return "filtered"
    return "unknown"

# Function to scan a given target on specified ports
def scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts):
    """
    TODO:
    - Print the scanning message with the target IP and port range.
    - Use `is_host_online(target)` to check if the host is reachable.
    - If the host is online, iterate through the ports and:
        - Call `syn_scan(target, port)` for each port.
        - Categorize the result into open, closed, or filtered lists.
    """
    print(f"[+] Scanning {target} on ports {min(ports)}-{max(ports)}...")

    if not is_host_online(target):
        print(f"[-] {target} is unreachable. Skipping...")
        return

    for port in ports:
        print(f"[+] Scanning {target}:{port}...")
        result = syn_scan(target, port)

        if result == "open":
            open_hosts.append((target, port))
        elif result == "closed":
            closed_hosts.append((target, port))
        elif result == "filtered":
            filtered_hosts.append((target, port))


def parse_subnet_range(ipv4):
    subnet_mask = ipv4.split('/')[1]
    available_addresses = 2**(32 - int(subnet_mask))
    formatted_ip = '.'.join(ipv4.split('.')[0:3])
    start, end = formatted_ip + '.1', formatted_ip + '.' + str(available_addresses  - 1)
    parse_multiple_ip(start + '-' + end)



def parse_multiple_ip(targets) -> list:
    ip_addresses = []
    start, end = targets.split('-')
    if (start.count('.') != 3 or end.count('.') != 3):
        raise ValueError("IP Addresses must have 4 periods to be valid")
    start_range, end_range = int(start.split('.')[3]), int(end.split('.')[3])
    prefix = '.'.join(start.split('.')[0:3]) + '.'
    for i in range(start_range, end_range + 1):
        ipv4 = prefix + str(i)
        ip_addresses.append(ipv4)
    print(ip_addresses)
    return ip_addresses

# Function to parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="SYN Scanner Shell for Students")
    parser.add_argument("-t", "--target", help="Target IP, range, or subnet")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., 80,443,1-100)")
    parser.add_argument("--show", help="Filter results: open, closed, filtered")

    args = parser.parse_args()

    if not args.target:
        args.target = get_local_subnet()


    # TODO: Implement target parsing (supporting single IP, range, subnet)
    targets = parse_multiple_ip(args.target) if '-' in args.target else parse_subnet_range(args.target)

    # TODO: Implement port parsing (supporting single ports, ranges, lists)
    ports = [80, 443]  # Placeholder (only scans 80 and 443)

    return targets, ports

if __name__ == "__main__":
    """
    TODO:
    - Call `parse_arguments()` to get the list of targets and ports.
    - Create empty lists for open, closed, and filtered ports.
    - Loop through each target and call `scan_target()`.
    - Print a final summary of open, closed, and filtered ports.
    """
    # targets = ['127.0.0.1']
    targets, ports = parse_arguments()
    ports = [80, 443, 22]

    # open_hosts = []
    # closed_hosts = []
    # filtered_hosts = []

    # print("\n[+] Starting scan...")
    # for target in targets:
    #     scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts)

    # print("\n[+] Scan Summary:")
    # print(f"  Open Ports: {open_hosts}")
    # print(f"  Closed Ports: {closed_hosts}")
    # print(f"  Filtered Ports: {filtered_hosts}")
