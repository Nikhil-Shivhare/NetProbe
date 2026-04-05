#!/usr/bin/python3

from scapy.all import *
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time


# Common ports mapped to service names
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017:"MongoDB",
}


class networkScanner:
    def __init__(self, hosts, threads=10, ports=None, skip_ports=False):
        self.threads    = threads
        self.ports      = ports if ports else list(COMMON_PORTS.keys())
        self.skip_ports = skip_ports

        for host in hosts:
            self.host     = host
            self.alive    = {}       # { ip: mac }
            self.os_info  = {}       # { ip: "OS [TTL]" }
            self.port_info = {}      # { ip: ["80/HTTP", "443/HTTPS", ...] }

            print(f"\n[*] Scanning target: {host}")
            start = time.time()

            self.create_packet()
            self.send_packet()
            self.get_alive()

            elapsed = time.time() - start
            print(f"[✓] Scan completed in {elapsed:.2f}s — {len(self.alive)} host(s) found\n")

            self.print_alive()

    # ─── ARP Discovery ────────────────────────────────────────────────────────

    def create_packet(self):
        layer1      = Ether(dst='ff:ff:ff:ff:ff:ff')
        layer2      = ARP(pdst=self.host)
        self.packet = layer1 / layer2

    def send_packet(self):
        ans, unasw = srp(self.packet, timeout=1, verbose=False)
        if ans:
            self.ans = ans
        else:
            print("[!] No hosts are up.")
            sys.exit(1)

    # ─── OS Fingerprinting (concurrent) ───────────────────────────────────────

    def get_alive(self):
        # Phase 1: Extract IP + MAC from ARP replies
        for _, received in self.ans:
            ip  = received.psrc
            mac = received.hwsrc
            self.alive[ip]     = mac
            self.port_info[ip] = []

        total = len(self.alive)

        # Phase 2: Concurrent OS fingerprinting
        print(f"[*] OS fingerprinting {total} host(s) — {self.threads} threads...")
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.detect_os_ttl, ip): ip for ip in self.alive}
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    os_name, ttl     = future.result()
                    self.os_info[ip] = f"{os_name} [{ttl}]"
                except Exception:
                    self.os_info[ip] = "Unknown [NA]"

        # Phase 3: Concurrent Port Scanning (skippable via --no-ports)
        if not self.skip_ports:
            print(f"[*] Port scanning {total} host(s) — {len(self.ports)} ports each...")
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                futures = {ex.submit(self.scan_ports, ip): ip for ip in self.alive}
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        self.port_info[ip] = future.result()
                    except Exception:
                        self.port_info[ip] = []

    # ─── TTL-based OS Detection ───────────────────────────────────────────────

    def detect_os_ttl(self, ip):
        try:
            reply = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
            if reply is None:
                return "Unknown", "NA"
            ttl = reply.ttl
            if   60  <= ttl <= 70:  return "Linux/macOS", ttl
            elif 110 <= ttl <= 130: return "Windows",     ttl
            elif 240 <= ttl <= 255: return "Net Device",  ttl
            else:                   return "Unknown",      ttl
        except Exception:
            return "Unknown", "NA"

    # ─── TCP SYN Port Scanner ─────────────────────────────────────────────────

    def scan_ports(self, ip):
        """Send TCP SYN to each port, collect those that reply SYN-ACK."""
        open_ports = []

        def probe(port):
            try:
                pkt   = IP(dst=ip) / TCP(dport=port, flags="S")
                reply = sr1(pkt, timeout=0.5, verbose=False)

                if reply and reply.haslayer(TCP):
                    # SYN-ACK (flags=0x12) means port is open
                    if reply[TCP].flags == 0x12:
                        # Send RST to close the half-open connection cleanly
                        send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
                        service = COMMON_PORTS.get(port, "unknown")
                        return f"{port}/{service}"
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            results = ex.map(probe, self.ports)

        open_ports = [r for r in results if r is not None]
        return sorted(open_ports, key=lambda x: int(x.split("/")[0]))

    # ─── Output Table ─────────────────────────────────────────────────────────

    def print_alive(self):
        if self.skip_ports:
            headers = ["IP", "MAC", "VENDOR", "OS (TTL)"]
        else:
            headers = ["IP", "MAC", "VENDOR", "OS (TTL)", "OPEN PORTS"]

        table = PrettyTable(headers)
        table.max_width = 50

        for ip, mac in self.alive.items():
            try:
                vendor = MacLookup().lookup(mac)
            except Exception:
                vendor = "NA"

            os_data = self.os_info.get(ip, "Unknown")

            if self.skip_ports:
                table.add_row([ip, mac, vendor, os_data])
            else:
                ports     = self.port_info.get(ip, [])
                ports_str = ", ".join(ports) if ports else "none"
                table.add_row([ip, mac, vendor, os_data, ports_str])

        print(table)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def get_args():
    parser = ArgumentParser(
        description="NetProbe — Network Reconnaissance Tool",
        epilog="Example: sudo python3 Network_scanner.py --h 192.168.1.0/24 --threads 20"
    )
    parser.add_argument("--h", dest="hosts", nargs="+",
                        help="Hosts or CIDR ranges to scan")
    parser.add_argument("--threads", "-t", dest="threads", type=int, default=10,
                        help="Thread count for OS fingerprinting & port scanning (default: 10)")
    parser.add_argument("--ports", "-p", dest="ports", nargs="+", type=int,
                        help="Custom port list to scan (e.g. --ports 22 80 443)")
    parser.add_argument("--no-ports", dest="no_ports", action="store_true",
                        help="Skip port scanning, show only host/OS info")

    arg = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return arg.hosts, arg.threads, arg.ports, arg.no_ports


hosts, threads, ports, no_ports = get_args()
networkScanner(hosts, threads=threads, ports=ports, skip_ports=no_ports)