from ipaddress import ip_address
import argparse
import socket
import subprocess
import re

from netaddr.ip.rfc1924 import BASE_85_DICT
from scapy.all import *
from netaddr import IPNetwork, IPRange  # Ensure netaddr is installed
from tokenize import String

def get_local_subnet():
    """
    Detects the local subnet by parsing the output of `ifconfig route`.
    """
    try:
        result = subprocess.run(["ifconfig", "route"], capture_output=True, text=True)

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
    syn_ack = sr1(packet, timeout=1, verbose=False)
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
    Scans a target on specified ports and updates the respective lists.

    @param target: Target IP address
    @param ports: List of ports to scan
    @param open_hosts: List to store open ports
    @param closed_hosts: List to store closed ports
    @param filtered_hosts: List to store filtered ports
    @return: None
    """

    if len(ports) < 10:
        print(f"[+] Scanning {target} on ports {ports}...")
    else:
        print(f"[+] Scanning {target} on ports {min(ports)} - {max(ports)}")

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
    """
    Parses an IPv4 address or subnet and returns a list of IP addresses.
    """
    subnet_mask = ipv4.split('/')[1]
    available_addresses = 2**(32 - int(subnet_mask))
    formatted_ip = '.'.join(ipv4.split('.')[0:3])
    start, end = formatted_ip + '.1', formatted_ip + '.' + str(available_addresses  - 1)
    return parse_multiple_ip(start + '-' + end)


def is_valid_ip(targets):
    """
    Checks if the target is a valid IPv4 address by checking length of portions and if they are integers.
    """
    if '-' not in targets:
        parts = targets.split('.')
        if len(parts) != 4 or not all(part.isdigit() for part in parts):
            return False
        return True
    return False

def parse_multiple_ip(targets):
    """
    Parses a range of IP addresses and returns a list of IP addresses.
    """
    ip_addresses = []
    if '-' not in targets and ',' not in targets:
        if not is_valid_ip(targets):
            print ("IP Addresses must be integers and have 3 periods to be valid")
            exit()
        else:
            return [targets]
    if ',' in targets:
        targets = targets.split(',')
        return targets

    start, end = targets.split('-')
    if (end == ''):
        print("Missing End Address")
        exit()
    if not is_valid_ip(start) or not is_valid_ip(end):
        print ("IP Addresses must be integers and have 3 periods to be valid")
        exit()
    start_range, end_range = int(start.split('.')[3]), int(end.split('.')[3])
    prefix = '.'.join(start.split('.')[0:3]) + '.'
    for i in range(start_range, end_range + 1):
        ipv4 = prefix + str(i)
        ip_addresses.append(ipv4)
    return ip_addresses

def parse_ports(ports):
    """
    Parses a range of ports and returns a list of ports.
    """
    p_args = ports.split(",")
    filtered_ports = []
    for port in p_args:
        if "-" in port:
            start, end = port.split("-")
            for i in range(int(start), int(end)+1):
                filtered_ports.append(i)
        else:
            filtered_ports.append(int(port))
    return filtered_ports

def show_summary(show: str, open: list, closed: list, filtered:list) -> None:
    print("\n[+] Scan Summary:")
    filters = ["open", "closed", "filtered"]
    if show != None and "," in show:
        filters = show.split(",")
    else:
        filters = [show]
    for filter in filters:
        match filter:
            case "open":
                print(f"  Open Ports: {open_hosts}")
            case "closed":
                print(f"  Closed Ports: {closed_hosts}")
            case "filtered":
                print(f"  Filtered Ports: {filtered_hosts}")
            case _:
                print(f"  Open Ports: {open_hosts}")
                print(f"  Closed Ports: {closed_hosts}")
                print(f"  Filtered Ports: {filtered_hosts}")


def parse_arguments():
    parser = argparse.ArgumentParser(description="SYN Scanner Shell for Students")
    parser.add_argument("-t", "--target", help="Target IP, range, or subnet")
    parser.add_argument("-p", "--ports", help="Port(s) to scan (e.g., 80,443,1-100)")
    parser.add_argument("--show", help="Filter results: open, closed, filtered")

    args = parser.parse_args()
    if args.target == None and args.ports == None and args.show == None:
        parser.print_help()
        exit()
    if args.target == "" and args.ports == "":
        print("[+] No target and ports specified: Searching local subnet and all ports.")

    if not args.target:
        targets = parse_subnet_range(get_local_subnet())
    else:
        targets = parse_subnet_range(args.target) if '/' in args.target else parse_multiple_ip(args.target)
    # Implement port parsing (supporting single ports, ranges, lists)
    ports = parse_ports(args.ports) if args.ports else list(range(1,65535+1))

    show = args.show


    return targets, ports, show


if __name__ == "__main__":
    """
    TODO:
    - Call `parse_arguments()` to get the list of targets and ports.
    - Create empty lists for open, closed, and filtered ports.
    - Loop through each target and call `scan_target()`.
    - Print a final summary of open, closed, and filtered ports.
    """
    # targets = ['127.0.0.1']
    targets, ports, show = parse_arguments()

    open_hosts = []
    closed_hosts = []
    filtered_hosts = []


    print("\n[+] Starting scan...")
    for target in targets:
        scan_target(target, ports, open_hosts, closed_hosts, filtered_hosts)

    show_summary(show, open_hosts, closed_hosts, filtered_hosts)
