# port_scanner.py — TCP SYN port scanning

import logging
from concurrent.futures import ThreadPoolExecutor
from scapy.all import IP, TCP, sr1, send
from netprobe.ports import ALL_PORTS

log = logging.getLogger("netprobe")


def scan_ports(ip, ports, threads=10, pbar=None):
    """TCP SYN scan across the given ports for a single IP.

    Returns a sorted list of strings like ["22/SSH", "80/HTTP"].
    """
    def probe(port):
        try:
            log.debug(f"Probing {ip}:{port}")
            pkt   = IP(dst=ip) / TCP(dport=port, flags="S")
            reply = sr1(pkt, timeout=0.5, verbose=False)
            if reply and reply.haslayer(TCP) and reply[TCP].flags == 0x12:
                send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=False)
                service = ALL_PORTS.get(port, "unknown")
                log.debug(f"Open: {ip}:{port} ({service})")
                return f"{port}/{service}"
        except Exception:
            pass
        finally:
            if pbar:
                pbar.update(1)
        return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        results = list(ex.map(probe, ports))

    open_ports = [r for r in results if r is not None]
    return sorted(open_ports, key=lambda x: int(x.split("/")[0]))
