#!/usr/bin/env python3
"""
Multi-threaded TCP port scanner with lightweight service detection.

For authorised security testing and learning only. Only scan hosts you own
or have explicit written permission to test.

Author: Usman Faraz (https://github.com/usmanfarazz)
"""

import argparse
import csv
import json
import os
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
    # extra services often seen in labs and CTFs
    88: "Kerberos", 389: "LDAP", 636: "LDAPS", 873: "rsync", 2049: "NFS",
    5985: "WinRM", 5986: "WinRM-HTTPS", 9200: "Elasticsearch", 11211: "Memcached",
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
        try:
            if "-" in part:
                start, end = sorted(int(x) for x in part.split("-", 1))
                ports.update(range(start, end + 1))
            elif part:
                ports.add(int(part))
        except ValueError:
            raise ValueError(f"invalid port or range: '{part}'") from None
    return sorted(p for p in ports if 0 < p < 65536)


def save_results(path: str, host: str, target_ip: str, ports_scanned: int,
                 started: datetime, results: list):
    """Write results to .json or .csv, picked from the file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        report = {
            "host": host,
            "ip": target_ip,
            "started": started.isoformat(timespec="seconds"),
            "ports_scanned": ports_scanned,
            "open_ports": results,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    elif ext == ".csv":
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["host", "ip", "port", "service", "banner"])
            writer.writeheader()
            for r in results:
                writer.writerow({"host": host, "ip": target_ip, **r})
    else:
        raise ValueError("output file must end in .json or .csv")


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
    parser.add_argument("-o", "--output",
                        help="Save results to a file: report.json or report.csv")
    args = parser.parse_args()

    if args.threads < 1:
        sys.exit("[!] --threads must be at least 1")
    if args.timeout <= 0:
        sys.exit("[!] --timeout must be greater than 0")
    if args.output and os.path.splitext(args.output)[1].lower() not in (".json", ".csv"):
        sys.exit("[!] --output must end in .json or .csv")

    try:
        target_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve host: {args.host}")

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        sys.exit(f"[!] {exc}")
    started = datetime.now()
    print(f"[*] Scanning {args.host} ({target_ip})")
    print(f"[*] {len(ports)} ports | {args.threads} threads | started {started:%H:%M:%S}\n")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_port, target_ip, p, args.timeout): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    elapsed = (datetime.now() - started).total_seconds()

    if not open_ports:
        print(f"[-] No open ports found ({elapsed:.1f}s).")
    else:
        print(f"{'PORT':<8}{'SERVICE':<14}BANNER")
        print("-" * 50)
        for r in open_ports:
            print(f"{r['port']:<8}{r['service']:<14}{r['banner']}")
        print(f"\n[+] Done in {elapsed:.1f}s. {len(open_ports)} open port(s) found.")

    if args.output:
        save_results(args.output, args.host, target_ip, len(ports), started, open_ports)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Scan interrupted by user.")
