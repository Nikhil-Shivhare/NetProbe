# validator.py — Input validation for NetProbe CLI arguments

import ipaddress
import sys


def validate_targets(hosts):
    """Validate a list of IP addresses or CIDR ranges.

    Accepts:
        - Single IP:    192.168.1.1
        - CIDR range:   192.168.1.0/24
        - Host ranges:  192.168.1.1-10  (not supported — inform user)

    Exits with a friendly message on invalid input.
    """
    errors = []
    for host in hosts:
        try:
            # Try as a network (CIDR) first
            net = ipaddress.ip_network(host, strict=False)
            # Warn on excessively large scans
            if net.num_addresses > 65536:
                print(f"  [!] Warning: {host} contains {net.num_addresses:,} addresses — this may take a very long time.")
        except ValueError:
            errors.append(f"  ✗  Invalid target: '{host}'  →  expected an IP (192.168.1.1) or CIDR (192.168.1.0/24)")

    if errors:
        print("\n[!] Invalid target(s) detected:\n")
        for e in errors:
            print(e)
        print()
        sys.exit(1)


def validate_ports(ports):
    """Validate a list of port numbers (must be integers 1–65535).

    Exits with a friendly message on invalid input.
    """
    if ports is None:
        return  # using defaults — no validation needed

    errors = []
    for p in ports:
        if not (1 <= p <= 65535):
            errors.append(f"  ✗  Invalid port: {p}  →  ports must be between 1 and 65535")

    if errors:
        print("\n[!] Invalid port(s) detected:\n")
        for e in errors:
            print(e)
        print()
        sys.exit(1)


def validate_threads(n):
    """Validate thread count (must be a positive integer, max 500).

    Exits with a friendly message on invalid input.
    """
    if n < 1:
        print(f"\n[!] Invalid thread count: {n}  →  must be at least 1\n")
        sys.exit(1)
    if n > 500:
        print(f"\n[!] Thread count too high: {n}  →  maximum allowed is 500\n")
        sys.exit(1)
