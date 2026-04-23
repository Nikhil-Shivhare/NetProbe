# scanner.py — NetworkScanner orchestration class

import sys
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from scapy.all import Ether, ARP, srp

from netprobe.ports import COMMON_PORTS, ALL_PORTS
from netprobe.os_fingerprint import detect_os
from netprobe.port_scanner import scan_ports
from netprobe.output import print_results

log = logging.getLogger("netprobe")


class NetworkScanner:
    """ARP-based network scanner with OS fingerprinting and port scanning."""

    def __init__(self, hosts, threads=10, ports=None, skip_ports=False, all_ports=False):
        self.threads    = threads
        self.skip_ports = skip_ports
        
        if ports:
            self.ports = ports
        elif all_ports:
            self.ports = list(ALL_PORTS.keys())
        else:
            self.ports = list(COMMON_PORTS.keys())

        for host in hosts:
            self.host      = host
            self.alive     = {}      # { ip: mac }
            self.os_info   = {}      # { ip: "OS [TTL]" }
            self.port_info = {}      # { ip: ["80/HTTP", ...] }

            print(f"\n[*] Scanning target: {host}")
            log.info(f"Starting scan on {host} | threads={self.threads} | ports={len(self.ports)}")
            start = time.time()

            self._create_packet()
            if not self._send_packet():
                continue
            self._run_scan()

            elapsed = time.time() - start
            print(f"[✓] Scan completed in {elapsed:.2f}s — {len(self.alive)} host(s) found\n")
            log.info(f"Scan done: {len(self.alive)} hosts up in {elapsed:.2f}s")

            print_results(self.alive, self.os_info, self.port_info, self.skip_ports)

    # ─── ARP Discovery ────────────────────────────────────────────────────────

    def _create_packet(self):
        log.debug(f"Building ARP broadcast packet for {self.host}")
        layer1      = Ether(dst='ff:ff:ff:ff:ff:ff')
        layer2      = ARP(pdst=self.host)
        self.packet = layer1 / layer2

    def _send_packet(self):
        log.debug("Sending ARP broadcast and waiting for replies...")
        ans, _ = srp(self.packet, timeout=1, verbose=False)
        if ans:
            self.ans = ans
            log.debug(f"ARP: received {len(ans)} reply(ies)")
            return True
        else:
            log.warning(f"No hosts responded to ARP broadcast on {self.host}")
            print(f"[!] No hosts are up on {self.host}.")
            return False

    # ─── Phase 2 + 3: OS Fingerprint & Port Scan (concurrent) ────────────────

    def _run_scan(self):
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
            futures = {ex.submit(detect_os, ip): ip for ip in self.alive}
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
                    futures = {
                        ex.submit(scan_ports, ip, self.ports, self.threads, pbar): ip
                        for ip in self.alive
                    }
                    for future in as_completed(futures):
                        ip = futures[future]
                        try:
                            self.port_info[ip] = future.result()
                            log.debug(f"Open ports on {ip}: {self.port_info[ip]}")
                        except Exception as e:
                            self.port_info[ip] = []
                            log.warning(f"Port scan failed for {ip}: {e}")


# ─── Console Entry Point ──────────────────────────────────────────────────────

def main():
    """Entry point for the `netprobe` console command (via pyproject.toml)."""
    import sys
    import argparse
    import logging

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        level=logging.WARNING,
    )
    _log = logging.getLogger("netprobe")

    BANNER = r"""
 _   _      _   ____            _
| \ | | ___| |_|  _ \ _ __ ___| |__   ___
|  \| |/ _ \ __| |_) | '__/ _ \ '_ \ / _ \
| |\  |  __/ |_|  __/| | |  __/ |_) |  __/
|_| \_|\___|\___|_|   |_|  \___|_.__/ \___|

  ARP Discovery  ·  OS Fingerprinting  ·  Port Scanning
"""

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=BANNER,
    )
    parser.add_argument(
        "--h", dest="hosts", nargs="+", metavar="TARGET",
        help="Host IP or CIDR range(s) to scan  e.g. 192.168.1.0/24",
    )
    parser.add_argument(
        "--threads", "-t", dest="threads", type=int, default=10, metavar="N",
        help="Thread count for concurrent tasks  (default: 10)",
    )
    parser.add_argument(
        "--ports", "-p", dest="ports", nargs="+", type=int, metavar="PORT",
        help="Custom port list  e.g. --ports 22 80 443",
    )
    parser.add_argument(
        "--no-ports", dest="no_ports", action="store_true",
        help="Skip port scanning — host + OS only",
    )
    parser.add_argument(
        "--all-ports", dest="all_ports", action="store_true",
        help="Scan all 501 ports (default is 101 common ports)",
    )
    parser.add_argument(
        "--verbose", "-v", dest="verbose", action="store_true",
        help="Enable timestamped DEBUG logging",
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    arg = parser.parse_args()

    if arg.verbose:
        _log.setLevel(logging.DEBUG)

    NetworkScanner(
        arg.hosts,
        threads=arg.threads,
        ports=arg.ports,
        skip_ports=arg.no_ports,
        all_ports=arg.all_ports,
    )

