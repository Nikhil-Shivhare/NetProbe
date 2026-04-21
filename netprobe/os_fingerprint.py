# os_fingerprint.py — Combined TTL + TCP Window Size OS detection

import logging
from scapy.all import IP, TCP, ICMP, sr1, send

log = logging.getLogger("netprobe")

# ─── Known TCP Window-Size Signatures (SYN-ACK) ──────────────────────────────

WIN_LINUX   = {5840, 5720, 14600, 29200, 26883, 64240, 32120}
WIN_WINDOWS = {65535, 8192, 64240, 64512, 16384}
WIN_MACOS   = {65535, 65160}
WIN_NETDEV  = {4128, 8192, 16384, 32768}

SYN_PROBE_PORT = 80  # default port used for TCP window probe


# ─── Public API ───────────────────────────────────────────────────────────────

def detect_os(ip, syn_probe_port=SYN_PROBE_PORT):
    """Combined ICMP-TTL + TCP-Window-Size OS fingerprinting.

    Returns a formatted string like:
        "Linux [TTL:64 WIN:29200] (high)"
    """
    ttl      = None
    win_size = None
    os_ttl   = "Unknown"
    os_win   = "Unknown"

    # ── Probe 1: ICMP (TTL) ───────────────────────────────────────────────
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

    # ── Probe 2: TCP SYN → Window Size ────────────────────────────────────
    try:
        log.debug(f"Sending TCP SYN to {ip}:{syn_probe_port}")
        syn_pkt   = IP(dst=ip) / TCP(dport=syn_probe_port, flags="S")
        syn_reply = sr1(syn_pkt, timeout=1, verbose=False)
        if syn_reply and syn_reply.haslayer(TCP) and syn_reply[TCP].flags == 0x12:
            win_size = syn_reply[TCP].window
            send(IP(dst=ip) / TCP(dport=syn_probe_port, flags="R"), verbose=False)
            log.debug(f"TCP window for {ip}: {win_size}")
            if   win_size in WIN_LINUX:   os_win = "Linux"
            elif win_size in WIN_MACOS:   os_win = "macOS"
            elif win_size in WIN_WINDOWS: os_win = "Windows"
            elif win_size in WIN_NETDEV:  os_win = "Net Device"
    except Exception as e:
        log.warning(f"TCP SYN probe failed for {ip}: {e}")

    # ── Combine both signals ──────────────────────────────────────────────
    os_name, confidence = _combine_os(os_ttl, os_win, ttl, win_size)
    ttl_str = ttl if ttl is not None else "NA"
    win_str = win_size if win_size is not None else "NA"
    detail  = f"{os_name} [TTL:{ttl_str} WIN:{win_str}] ({confidence})"
    log.debug(f"OS result {ip}: {detail}")
    return detail


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
