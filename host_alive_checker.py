#!/usr/bin/env python3
"""
Host Alive Checker - Check which hosts are accessible on common web ports
==========================================================================
Checks a list of hosts for accessibility on ports like 80, 443, 8080, 8443.

Usage:
  python3 host_alive_checker.py -i hosts.txt -o alive_results.csv
  python3 host_alive_checker.py -i hosts.txt -o alive_results.csv --ports 80,443,8080,8443,3000
  python3 host_alive_checker.py -i hosts.txt -o alive_results.csv --timeout 5 --threads 10

Author: Security Lab Tool
"""

import argparse
import csv
import os
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse


# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
DEFAULT_PORTS = [80, 443, 8080, 8443]


def extract_hostname(entry):
    """Extract hostname from a URL or plain hostname string."""
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None

    # If it looks like a URL, parse out the hostname
    if "://" in entry:
        parsed = urlparse(entry)
        return parsed.hostname
    # Could be host:port format
    if ":" in entry and not entry.startswith("["):
        return entry.split(":")[0]
    return entry


def check_port(host, port, timeout=5):
    """
    Check if a specific port is accessible on the host.
    Returns a dict with port, status, and optional details.
    """
    result = {"port": port, "open": False, "protocol": None, "details": ""}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn_result = sock.connect_ex((host, port))

        if conn_result == 0:
            result["open"] = True

            # Try to detect if it's serving HTTPS/TLS
            if port in (443, 8443) or port >= 1024:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        result["protocol"] = "HTTPS/TLS"
                        result["details"] = f"TLS {ssock.version()}"
                except (ssl.SSLError, OSError):
                    if port in (443, 8443):
                        result["protocol"] = "TCP Open (TLS handshake failed)"
                    else:
                        result["protocol"] = "HTTP"
                    # Re-create socket since the TLS attempt consumed it
            else:
                result["protocol"] = "HTTP"
        else:
            result["details"] = "Connection refused or filtered"

        sock.close()
    except socket.timeout:
        result["details"] = "Timed out"
    except socket.gaierror:
        result["details"] = "DNS resolution failed"
    except OSError as e:
        result["details"] = str(e)[:100]

    return result


def check_host(host, ports, timeout=5):
    """Check all ports for a single host."""
    result = {
        "host": host,
        "dns_resolved": False,
        "ip_address": "",
        "port_results": [],
    }

    # DNS resolution check first
    try:
        ip = socket.gethostbyname(host)
        result["dns_resolved"] = True
        result["ip_address"] = ip
    except socket.gaierror:
        result["ip_address"] = "N/A"
        # All ports will fail, mark them
        for port in ports:
            result["port_results"].append(
                {"port": port, "open": False, "protocol": None, "details": "DNS resolution failed"}
            )
        return result

    # Check each port
    for port in ports:
        port_result = check_port(host, port, timeout)
        result["port_results"].append(port_result)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Host Alive Checker - Check host accessibility on common web ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i hosts.txt -o alive_results.csv
  %(prog)s -i hosts.txt -o alive_results.csv --ports 80,443,8080,8443,3000
  %(prog)s -i hosts.txt -o alive_results.csv --timeout 5 --threads 10

Input file format (hosts.txt) - same as web_security_scanner.py:
  example.com
  https://test.site.com
  http://vulnerable-app.local
        """,
    )
    parser.add_argument(
        "-i", "--input", required=True, help="Input text file with hosts/URLs (one per line)"
    )
    parser.add_argument(
        "-o", "--output", required=True, help="Output CSV file path"
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help=f"Comma-separated list of ports to check (default: {','.join(str(p) for p in DEFAULT_PORTS)})",
    )
    parser.add_argument(
        "--timeout", type=int, default=5, help="Connection timeout in seconds per port (default: 5)"
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)"
    )

    args = parser.parse_args()

    # Parse ports
    try:
        ports = [int(p.strip()) for p in args.ports.split(",")]
    except ValueError:
        print("[!] Invalid port list. Use comma-separated integers (e.g., 80,443,8080)")
        sys.exit(1)

    # Read hosts
    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)

    with open(args.input, "r") as f:
        raw_lines = [line.strip() for line in f.readlines() if line.strip() and not line.strip().startswith("#")]

    # Extract hostnames (dedup while preserving order)
    seen = set()
    hosts = []
    for line in raw_lines:
        hostname = extract_hostname(line)
        if hostname and hostname not in seen:
            seen.add(hostname)
            hosts.append(hostname)

    if not hosts:
        print("[!] No hosts found in input file.")
        sys.exit(1)

    print(f"[*] Loaded {len(hosts)} unique host(s) from {args.input}")
    print(f"[*] Ports to check: {', '.join(str(p) for p in ports)}")
    print(f"[*] Scanning with {args.threads} thread(s), timeout={args.timeout}s per port...")
    print("-" * 70)

    # Scan
    results = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_host = {
            executor.submit(check_host, host, ports, args.timeout): host
            for host in hosts
        }

        for i, future in enumerate(as_completed(future_to_host), 1):
            host = future_to_host[future]
            try:
                result = future.result()
                results.append(result)

                open_ports = [str(pr["port"]) for pr in result["port_results"] if pr["open"]]
                status = "ALIVE" if open_ports else "DOWN"
                port_info = ", ".join(open_ports) if open_ports else "None"
                print(f"  [{i}/{len(hosts)}] {host} ({result['ip_address']}) - {status} | Open ports: {port_info}")

            except Exception as e:
                print(f"  [{i}/{len(hosts)}] {host} - ERROR: {e}")
                results.append({
                    "host": host,
                    "dns_resolved": False,
                    "ip_address": "N/A",
                    "port_results": [
                        {"port": p, "open": False, "protocol": None, "details": str(e)[:100]}
                        for p in ports
                    ],
                })

    # Write CSV
    print("-" * 70)
    print(f"[*] Writing results to {args.output}...")

    with open(args.output, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)

        # Header row
        header = ["Host", "IP Address", "Status", "Open Ports"]
        for port in ports:
            header.append(f"Port {port}")
        writer.writerow(header)

        for result in sorted(results, key=lambda x: x["host"]):
            open_ports = [str(pr["port"]) for pr in result["port_results"] if pr["open"]]
            status = "ALIVE" if open_ports else "DOWN"

            row = [
                result["host"],
                result["ip_address"],
                status,
                ", ".join(open_ports) if open_ports else "None",
            ]

            # Per-port columns
            for pr in result["port_results"]:
                if pr["open"]:
                    cell = f"OPEN ({pr['protocol'] or 'TCP'})"
                    if pr["details"]:
                        cell += f" [{pr['details']}]"
                else:
                    cell = f"CLOSED"
                    if pr["details"]:
                        cell += f" ({pr['details']})"
                row.append(cell)

            writer.writerow(row)

    # Summary
    alive_count = sum(1 for r in results if any(pr["open"] for pr in r["port_results"]))
    down_count = len(results) - alive_count

    print(f"[+] Done! Results saved to: {args.output}")
    print(f"[+] Total hosts scanned: {len(results)}")
    print(f"[+] Alive: {alive_count} | Down: {down_count}")

    # Port summary
    port_counts = {}
    for port in ports:
        count = sum(
            1 for r in results
            for pr in r["port_results"]
            if pr["port"] == port and pr["open"]
        )
        port_counts[port] = count
    print(f"[+] Port breakdown: {' | '.join(f'{p}: {c} open' for p, c in port_counts.items())}")


if __name__ == "__main__":
    main()
