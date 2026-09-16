#!/usr/bin/env python3
"""
Multi-threaded TCP port scanner with lightweight service detection.

For authorised security testing and learning only. Only scan hosts you own
or have explicit written permission to test.

Author: Usman Faraz (https://github.com/usmanfarazz)
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# A small map of well-known ports so the output is readable without nmap.
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def grab_banner(sock: socket.socket) -> str:
    """Try to read a short service banner; return '' if none is offered."""
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner.splitlines()[0][:60] if banner else ""
    except OSError:
        return ""


def scan_port(host: str, port: int, timeout: float):
    """Return a result dict if the port is open, else None."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return None
        service = COMMON_SERVICES.get(port, "unknown")
        return {"port": port, "service": service, "banner": grab_banner(sock)}


def parse_ports(spec: str):
    """Turn '22,80,1000-1010' into a sorted list of unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP port scanner with service detection."
    )
    parser.add_argument("host", help="Target hostname or IP address")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of worker threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Connection timeout in seconds (default: 0.5)")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve host: {args.host}")

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.host} ({target_ip})")
    print(f"[*] {len(ports)} ports | {args.threads} threads | started {datetime.now():%H:%M:%S}\n")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, target_ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if not open_ports:
        print("[-] No open ports found.")
        return

    print(f"{'PORT':<8}{'SERVICE':<14}BANNER")
    print("-" * 50)
    for r in sorted(open_ports, key=lambda x: x["port"]):
        print(f"{r['port']:<8}{r['service']:<14}{r['banner']}")
    print(f"\n[+] Done. {len(open_ports)} open port(s) found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Scan interrupted by user.")
