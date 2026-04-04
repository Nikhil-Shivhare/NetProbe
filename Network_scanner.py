#!/usr/bin/python3

from scapy.all import *
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import time


class networkScanner:
    def __init__(self, hosts, threads=10):
        self.threads = threads
        for host in hosts:
            self.host = host
            self.alive = {}
            self.os_info = {}

            print(f"\n[*] Scanning target: {host}")
            start = time.time()

            self.create_packet()
            self.send_packet()
            self.get_alive()

            elapsed = time.time() - start
            print(f"[✓] Scan completed in {elapsed:.2f}s — {len(self.alive)} host(s) found")

            self.print_alive()

    def create_packet(self):
        layer1 = Ether(dst='ff:ff:ff:ff:ff:ff')
        layer2 = ARP(pdst=self.host)
        packet = layer1 / layer2
        self.packet = packet

    def send_packet(self):
        ans, unasw = srp(self.packet, timeout=1, verbose=False)
        if ans:
            self.ans = ans
        else:
            print(" No Host is Up")
            sys.exit(1)

    def get_alive(self):
        # Phase 1: Extract all IPs and MACs from ARP responses
        for sent, received in self.ans:
            ip = received.psrc
            mac = received.hwsrc
            self.alive[ip] = mac

        # Phase 2: Run OS detection concurrently using threads
        print(f"[*] Fingerprinting {len(self.alive)} host(s) with {self.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {
                executor.submit(self.detect_os_ttl, ip): ip
                for ip in self.alive.keys()
            }

            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    os_name, ttl = future.result()
                    self.os_info[ip] = f"{os_name} [{ttl}]"
                except Exception:
                    self.os_info[ip] = "Unknown [NA]"

    def detect_os_ttl(self, ip):
        try:
            pkt = IP(dst=ip) / ICMP()
            reply = sr1(pkt, timeout=1, verbose=False)

            if reply is None:
                return "Unknown", "NA"

            ttl = reply.ttl

            if 60 <= ttl <= 70:
                return "Linux/Unix/macOS", ttl
            elif 110 <= ttl <= 130:
                return "Windows", ttl
            elif 240 <= ttl <= 255:
                return "Network Device", ttl
            else:
                return "Unknown", ttl

        except Exception:
            return "Unknown", "NA"

    def print_alive(self):
        table = PrettyTable(["IP", "MAC", "VENDOR", "OS (TTL)"])

        for ip, mac in self.alive.items():
            try:
                vendor = MacLookup().lookup(mac)
            except Exception:
                vendor = "NA"

            os_data = self.os_info.get(ip, "Unknown")
            table.add_row([ip, mac, vendor, os_data])

        print(table)


def get_args():
    parser = ArgumentParser(description="NetProbe — Network Reconnaissance Tool")
    parser.add_argument("--h", dest="hosts", nargs="+", help="Hosts or CIDR ranges to scan")
    parser.add_argument("--threads", "-t", dest="threads", type=int, default=10,
                        help="Number of threads for OS fingerprinting (default: 10)")
    arg = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    return arg.hosts, arg.threads


hosts, threads = get_args()
networkScanner(hosts, threads)