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
        print(f"[*] OS fingerprinting {total} host(s) (TTL + TCP Window)...")
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.detect_os, ip): ip for ip in self.alive}
            with tqdm(total=total, desc="  OS Detect", unit="host",
                      bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]",
                      leave=False) as pbar:
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        self.os_info[ip] = future.result()
                        log.debug(f"OS detect {ip}: {self.os_info[ip]}")
                    except Exception as e:
                        self.os_info[ip] = "Unknown [TTL:NA WIN:NA] (low)"
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

    # ─── TTL + TCP Window OS Detection ───────────────────────────────────────

    # Known TCP window-size signatures (SYN-ACK)
    WIN_LINUX   = {5840, 5720, 14600, 29200, 26883, 64240, 32120}
    WIN_WINDOWS = {65535, 8192, 64240, 64512, 16384}
    WIN_MACOS   = {65535, 65160}
    WIN_NETDEV  = {4128, 8192, 16384, 32768}

    SYN_PROBE_PORT = 80  # port used for TCP window probe

    def detect_os(self, ip):
        """Combined ICMP-TTL + TCP-Window-Size OS fingerprinting."""
        ttl      = None
        win_size = None
        os_ttl   = "Unknown"
        os_win   = "Unknown"

        # ── Probe 1: ICMP (TTL) ───────────────────────────────────────────
        try:
            log.debug(f"Sending ICMP to {ip}")
            icmp_reply = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=False)
            if icmp_reply:
                ttl = icmp_reply.ttl
                if   60  <= ttl <= 70:  os_ttl = "Linux/macOS"
                elif 110 <= ttl <= 130: os_ttl = "Windows"
                elif 240 <= ttl <= 255: os_ttl = "Net Device"
        except Exception as e:
            log.warning(f"ICMP probe failed for {ip}: {e}")

        # ── Probe 2: TCP SYN → Window Size ────────────────────────────────
        try:
            log.debug(f"Sending TCP SYN to {ip}:{self.SYN_PROBE_PORT}")
            syn_pkt  = IP(dst=ip) / TCP(dport=self.SYN_PROBE_PORT, flags="S")
            syn_reply = sr1(syn_pkt, timeout=1, verbose=False)
            if syn_reply and syn_reply.haslayer(TCP) and syn_reply[TCP].flags == 0x12:
                win_size = syn_reply[TCP].window
                send(IP(dst=ip) / TCP(dport=self.SYN_PROBE_PORT, flags="R"), verbose=False)
                log.debug(f"TCP window for {ip}: {win_size}")
                if   win_size in self.WIN_LINUX:   os_win = "Linux"
                elif win_size in self.WIN_MACOS:   os_win = "macOS"
                elif win_size in self.WIN_WINDOWS: os_win = "Windows"
                elif win_size in self.WIN_NETDEV:  os_win = "Net Device"
        except Exception as e:
            log.warning(f"TCP SYN probe failed for {ip}: {e}")

        # ── Combine both signals ──────────────────────────────────────────
        os_name, confidence = self._combine_os(os_ttl, os_win, ttl, win_size)
        ttl_str = ttl if ttl is not None else "NA"
        win_str = win_size if win_size is not None else "NA"
        detail  = f"{os_name} [TTL:{ttl_str} WIN:{win_str}] ({confidence})"
        log.debug(f"OS result {ip}: {detail}")
        return detail

    @staticmethod
    def _combine_os(os_ttl, os_win, ttl, win_size):
        """Merge TTL and window-size guesses into one verdict + confidence."""
        # Neither probe succeeded
        if os_ttl == "Unknown" and os_win == "Unknown":
            return "Unknown", "low"

        # Only one probe succeeded
        if os_win == "Unknown":
            return os_ttl, "medium"
        if os_ttl == "Unknown":
            return os_win, "medium"

        # Both probes agree
        if os_ttl == os_win:
            return os_win, "high"

        # TTL says "Linux/macOS" — window size can disambiguate
        if os_ttl == "Linux/macOS":
            if os_win in ("Linux", "macOS"):
                return os_win, "high"
            # window says something else, trust TTL bucket
            return os_ttl, "medium"

        # TTL says Net Device — trust TTL (network gear TTL is very reliable)
        if os_ttl == "Net Device":
            return "Net Device", "high"

        # Conflicting — prefer TTL (more battle-tested)
        return os_ttl, "medium"

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

BANNER = r"""
 _   _      _   ____            _
| \ | | ___| |_|  _ \ _ __ ___| |__   ___
|  \| |/ _ \ __| |_) | '__/ _ \ '_ \ / _ \
| |\  |  __/ |_|  __/| | |  __/ |_) |  __/
|_| \_|\___|\__|_|   |_|  \___|_.__/ \___|

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
  OS (TTL)   →  Guessed OS via ICMP TTL
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

    return arg.hosts, arg.threads, arg.ports, arg.no_ports


hosts, threads, ports, no_ports = get_args()
networkScanner(hosts, threads=threads, ports=ports, skip_ports=no_ports)