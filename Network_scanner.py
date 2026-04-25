#!/usr/bin/python3
# Network_scanner.py — Thin CLI entry point (backward compatible)

import sys
import logging
from netprobe import NetworkScanner
from netprobe.validator import validate_targets, validate_ports, validate_threads

# ─── Logging Setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING      # default: silent; --verbose switches to DEBUG
)
log = logging.getLogger("netprobe")


# ─── CLI ──────────────────────────────────────────────────────────────────────

BANNER = r"""
 _   _      _   ____            _
| \ | | ___| |_|  _ \ _ __ ___| |__   ___
|  \| |/ _ \ __| |_) | '__/ _ \ '_ \ / _ \
| |\  |  __/ |_|  __/| | |  __/ |_) |  __/
|_| \_|\___|\___|_|   |_|  \___|_.__/ \___|

  ARP Discovery  ·  OS Fingerprinting  ·  Port Scanning
"""

EXAMPLES = """
─────────────────────────────────────────────────────
 EXAMPLES
─────────────────────────────────────────────────────

  Scan a full subnet (default 101 ports, 10 threads):
    sudo python3 Network_scanner.py --h 192.168.1.0/24

  Scan a single host:
    sudo python3 Network_scanner.py --h 192.168.1.1

  Scan multiple targets at once:
    sudo python3 Network_scanner.py --h 192.168.1.1 10.0.0.0/24

  Use more threads for faster scans on large subnets:
    sudo python3 Network_scanner.py --h 192.168.1.0/24 --threads 30

  Scan only specific ports:
    sudo python3 Network_scanner.py --h 192.168.1.0/24 --ports 22 80 443 3306

  Skip port scanning — host discovery + OS only (fastest):
    sudo python3 Network_scanner.py --h 192.168.1.0/24 --no-ports

  Enable verbose/debug logging:
    sudo python3 Network_scanner.py --h 192.168.1.1 --verbose

  Combine flags:
    sudo python3 Network_scanner.py --h 192.168.1.0/24 -t 20 -p 22 80 443 -v

─────────────────────────────────────────────────────
 OUTPUT COLUMNS
─────────────────────────────────────────────────────

  IP         →  IPv4 address of the live host
  MAC        →  Hardware (MAC) address
  VENDOR     →  NIC manufacturer resolved from MAC OUI
  OS (TTL)   →  Guessed OS via ICMP TTL + TCP Window
                  Linux/macOS → TTL ≈ 64
                  Windows     → TTL ≈ 128
                  Net Device  → TTL ≈ 255
  OPEN PORTS →  port/service  e.g. 22/SSH, 80/HTTP, 443/HTTPS

─────────────────────────────────────────────────────
"""


def get_args():
    import argparse
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=BANNER,
        epilog=EXAMPLES,
    )

    parser.add_argument(
        "--h", dest="hosts", nargs="+", metavar="TARGET",
        help="Host IP or CIDR range(s) to scan   e.g. 192.168.1.0/24"
    )
    parser.add_argument(
        "--threads", "-t", dest="threads", type=int, default=10, metavar="N",
        help="Thread count for concurrent tasks        (default: 10)"
    )
    parser.add_argument(
        "--ports", "-p", dest="ports", nargs="+", type=int, metavar="PORT",
        help="Custom port list to probe    e.g. --ports 22 80 443 3306"
    )
    parser.add_argument(
        "--no-ports", dest="no_ports", action="store_true",
        help="Skip port scanning — show host + OS info only"
    )
    parser.add_argument(
        "--all-ports", dest="all_ports", action="store_true",
        help="Scan all 501 ports (default is 101 common ports)"
    )
    parser.add_argument(
        "--verbose", "-v", dest="verbose", action="store_true",
        help="Enable timestamped DEBUG logging for every packet"
    )

    arg = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if arg.verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Verbose mode enabled")

    # ── Input validation ──────────────────────────────────────────────────
    validate_targets(arg.hosts)
    validate_ports(arg.ports)
    validate_threads(arg.threads)

    return arg.hosts, arg.threads, arg.ports, arg.no_ports, arg.all_ports


if __name__ == "__main__":
    hosts, threads, ports, no_ports, all_ports = get_args()
    NetworkScanner(hosts, threads=threads, ports=ports, skip_ports=no_ports, all_ports=all_ports)