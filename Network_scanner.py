#!/usr/bin/python3

from scapy.all import *
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import sys
import time
import logging
from ports import COMMON_PORTS

# ─── Logging Setup ────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    level=logging.WARNING      # default: silent; --verbose switches to DEBUG
)
log = logging.getLogger("netprobe")



class networkScanner:
    def __init__(self, hosts, threads=10, ports=None, skip_ports=False):
        self.threads    = threads
        self.ports      = ports if ports else list(COMMON_PORTS.keys())
        self.skip_ports = skip_ports

        for host in hosts:
            self.host      = host
            self.alive     = {}      # { ip: mac }
            self.os_info   = {}      # { ip: "OS [TTL]" }
            self.port_info = {}      # { ip: ["80/HTTP", ...] }

            print(f"\n[*] Scanning target: {host}")
            log.info(f"Starting scan on {host} | threads={self.threads} | ports={len(self.ports)}")
            start = time.time()

            self.create_packet()
            self.send_packet()
            self.get_alive()

            elapsed = time.time() - start
            print(f"[✓] Scan completed in {elapsed:.2f}s — {len(self.alive)} host(s) found\n")
            log.info(f"Scan done: {len(self.alive)} hosts up in {elapsed:.2f}s")

            self.print_alive()

    # ─── ARP Discovery ────────────────────────────────────────────────────────

    def create_packet(self):
        log.debug(f"Building ARP broadcast packet for {self.host}")
        layer1      = Ether(dst='ff:ff:ff:ff:ff:ff')
        layer2      = ARP(pdst=self.host)
        self.packet = layer1 / layer2

    def send_packet(self):
        log.debug("Sending ARP broadcast and waiting for replies...")
        ans, _ = srp(self.packet, timeout=1, verbose=False)
        if ans:
            self.ans = ans
            log.debug(f"ARP: received {len(ans)} reply(ies)")
        else:
            log.warning("No hosts responded to ARP broadcast")
            print("[!] No hosts are up.")
            sys.exit(1)

    # ─── Phase 2 + 3: OS Fingerprint & Port Scan (concurrent) ────────────────

    def get_alive(self):
        # Extract IP + MAC from ARP replies
        for _, received in self.ans:
            ip  = received.psrc
            mac = received.hwsrc
            self.alive[ip]     = mac
            self.port_info[ip] = []
            log.debug(f"ARP reply: {ip} is at {mac}")

        total = len(self.alive)

        # Phase 2: Concurrent OS fingerprinting with progress bar
        print(f"[*] OS fingerprinting {total} host(s)...")
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.detect_os_ttl, ip): ip for ip in self.alive}
            with tqdm(total=total, desc="  OS Detect", unit="host",
                      bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
                      leave=False) as pbar:
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        os_name, ttl      = future.result()
                        self.os_info[ip]  = f"{os_name} [{ttl}]"
                        log.debug(f"OS detect {ip}: {os_name} (TTL={ttl})")
                    except Exception as e:
                        self.os_info[ip] = "Unknown [NA]"
                        log.warning(f"OS detect failed for {ip}: {e}")
                    pbar.update(1)

        # Phase 3: Concurrent port scanning with progress bar
        if not self.skip_ports:
            total_probes = total * len(self.ports)
            print(f"[*] Port scanning {total} host(s) × {len(self.ports)} ports...")
            with tqdm(total=total_probes, desc="  Port Scan ", unit="probe",
                      bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}, {rate_fmt}]") as pbar:
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    futures = {ex.submit(self.scan_ports, ip, pbar): ip for ip in self.alive}
                    for future in as_completed(futures):
                        ip = futures[future]
                        try:
                            self.port_info[ip] = future.result()
                            log.debug(f"Open ports on {ip}: {self.port_info[ip]}")
                        except Exception as e:
                            self.port_info[ip] = []
                            log.warning(f"Port scan failed for {ip}: {e}")

    # ─── TTL-based OS Detection ───────────────────────────────────────────────

    def detect_os_ttl(self, ip):
        try:
            log.debug(f"Sending ICMP to {ip}")
            reply = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
            if reply is None:
                return "Unknown", "NA"
            ttl = reply.ttl
            if   60  <= ttl <= 70:  return "Linux/macOS",  ttl
            elif 110 <= ttl <= 130: return "Windows",       ttl
            elif 240 <= ttl <= 255: return "Net Device",    ttl
            else:                   return "Unknown",        ttl
        except Exception:
            return "Unknown", "NA"

    # ─── TCP SYN Port Scanner ─────────────────────────────────────────────────

    def scan_ports(self, ip, pbar=None):
        """TCP SYN scan across self.ports for a given IP."""
        open_ports = []

        def probe(port):
            try:
                log.debug(f"Probing {ip}:{port}")
                pkt   = IP(dst=ip) / TCP(dport=port, flags="S")
                reply = sr1(pkt, timeout=0.5, verbose=False)
                if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x12:
                    send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
                    service = COMMON_PORTS.get(port, "unknown")
                    log.debug(f"Open: {ip}:{port} ({service})")
                    return f"{port}/{service}"
            except Exception:
                pass
            finally:
                if pbar:
                    pbar.update(1)
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            results = list(ex.map(probe, self.ports))

        open_ports = [r for r in results if r is not None]
        return sorted(open_ports, key=lambda x: int(x.split("/")[0]))

    # ─── Output Table ─────────────────────────────────────────────────────────

    def print_alive(self):
        headers = ["IP", "MAC", "VENDOR", "OS (TTL)"]
        if not self.skip_ports:
            headers.append("OPEN PORTS")

        table           = PrettyTable(headers)
        table.max_width = 50
        table.align     = "l"

        for ip, mac in self.alive.items():
            try:
                vendor = MacLookup().lookup(mac)
            except Exception:
                vendor = "NA"

            os_data = self.os_info.get(ip, "Unknown")
            row     = [ip, mac, vendor, os_data]

            if not self.skip_ports:
                ports     = self.port_info.get(ip, [])
                ports_str = ", ".join(ports) if ports else "none"
                row.append(ports_str)

            table.add_row(row)

        print(table)


# ─── CLI ──────────────────────────────────────────────────────────────────────

def get_args():
    parser = ArgumentParser(
        description="NetProbe — Network Reconnaissance Tool",
        epilog="Example: sudo python3 Network_scanner.py --h 192.168.1.0/24 --threads 20 --verbose"
    )
    parser.add_argument("--h",         dest="hosts",    nargs="+",
                        help="Hosts or CIDR ranges to scan")
    parser.add_argument("--threads",   "-t", dest="threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--ports",     "-p", dest="ports",   nargs="+", type=int,
                        help="Custom ports to scan (e.g. --ports 22 80 443)")
    parser.add_argument("--no-ports",  dest="no_ports",  action="store_true",
                        help="Skip port scanning")
    parser.add_argument("--verbose",   "-v", dest="verbose",  action="store_true",
                        help="Enable verbose debug logging")

    arg = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Apply log level based on --verbose flag
    if arg.verbose:
        log.setLevel(logging.DEBUG)
        log.debug("Verbose mode enabled")

    return arg.hosts, arg.threads, arg.ports, arg.no_ports


hosts, threads, ports, no_ports = get_args()
networkScanner(hosts, threads=threads, ports=ports, skip_ports=no_ports)