# speed_test.py — Standalone internet speed test for NetProbe
#
# Measures the CURRENT MACHINE's connection to the internet via an
# Ookla speedtest server.  This is completely independent of the
# ARP/port scan pipeline and does NOT measure the speed of any
# scanned LAN host.
#
# Public API:
#   run_speed_test(server_id=None)  →  prints results and returns

from __future__ import annotations

import sys
import time
import logging
from typing import Optional

log = logging.getLogger("netprobe")

# ─── Bar helper ───────────────────────────────────────────────────────────────

def _speed_bar(mbps: float, max_mbps: float = 1000.0, width: int = 12) -> str:
    """Return a small ASCII progress bar proportional to *mbps*."""
    ratio   = min(mbps / max_mbps, 1.0)
    filled  = round(ratio * width)
    return "▓" * filled + "░" * (width - filled)


# ─── Result Printer ───────────────────────────────────────────────────────────

def _print_box(
    server_name: str,
    server_host: str,
    distance_km: float,
    ping_ms:     float,
    dl_mbps:     float,
    ul_mbps:     float,
    max_mbps:    float = 1000.0,
) -> None:
    """Print a fixed-width result box to stdout."""
    W = 49          # inner content width (between │ chars)
    bar = "─" * W

    def _row(label: str, value: str) -> str:
        label_col = f"{label:<10}"
        value_col = f"{value}"[:W - 13]          # guard against overflow
        pad       = " " * (W - 2 - len(label_col) - len(value_col))
        return f"  │  {label_col}  {value_col}{pad}│"

    dl_bar = _speed_bar(dl_mbps, max_mbps)
    ul_bar = _speed_bar(ul_mbps, max_mbps)

    print(f"\n  ┌{bar}┐")
    print(f"  │{'  NetProbe  ·  Internet Speed Test':<{W}}│")
    print(f"  ├{bar}┤")
    print(_row("Server",   server_name))
    print(_row("Host",     server_host))
    print(_row("Distance", f"{distance_km:.1f} km"))
    print(_row("Ping",     f"{ping_ms:.1f} ms"))
    print(_row("Download", f"{dl_mbps:.2f} Mbps  {dl_bar}"))
    print(_row("Upload",   f"{ul_mbps:.2f} Mbps  {ul_bar}"))
    print(f"  └{bar}┘")


# ─── Public API ───────────────────────────────────────────────────────────────

def run_speed_test(server_id: Optional[int] = None) -> None:
    """Run an internet speed test and print the results.

    Connects to an Ookla speedtest server, measures download speed,
    upload speed, and round-trip ping.  If *server_id* is given, that
    specific Ookla server is used; otherwise the nearest/fastest server
    is selected automatically.

    .. note::
        This tests **this machine's** internet connection — it does not
        measure the bandwidth of any host discovered by ARP scanning.

    Args:
        server_id: Optional Ookla server ID (integer) to force a specific
                   server.  Pass ``None`` to auto-select the best server.

    Side effects:
        Prints progress and results to stdout.  Calls ``sys.exit(1)`` on
        any unrecoverable error (no internet, bad server ID, etc.).
    """
    # ── Dependency check ──────────────────────────────────────────────────
    try:
        import speedtest as _st_mod
    except ImportError:
        print("[!] speedtest-cli is not installed.")
        print("    Install it with:  pip install speedtest-cli")
        sys.exit(1)

    # ── Preamble ──────────────────────────────────────────────────────────
    print("\n[*] Running Internet Speed Test...")
    print("    ⚠  Measures THIS machine's internet path to an Ookla server,")
    print("       not the network speed of any scanned LAN host.\n")

    start = time.time()

    try:
        st = _st_mod.Speedtest()

        # ── Server selection ──────────────────────────────────────────────
        if server_id is not None:
            print(f"    Locating server ID {server_id}...", end="", flush=True)
            try:
                servers = st.get_servers([server_id])
                if not servers:
                    print(f"\n    [!] Server {server_id} not found — falling back to best server.")
                    log.warning(f"Speed test: server ID {server_id} not found; using best server.")
                    st.get_best_server()
                else:
                    st.get_best_server(servers)
                    print("  done.")
            except _st_mod.NoMatchedServers:
                print(f"\n    [!] No server matched ID {server_id} — falling back to best server.")
                log.warning(f"Speed test: NoMatchedServers for ID {server_id}; using best server.")
                st.get_best_server()
        else:
            print("    Finding best server...", end="", flush=True)
            st.get_best_server()
            srv = st.results.server
            print(f"  {srv.get('sponsor', 'Unknown')}, {srv.get('name', '')}, "
                  f"{srv.get('country', '')}  ✓")
            log.debug(f"Speed test server: {srv}")

        # ── Download ──────────────────────────────────────────────────────
        print("    Testing download...", end="", flush=True)
        dl_bps  = st.download()
        dl_mbps = dl_bps / 1_000_000
        print(f"  {dl_mbps:.2f} Mbps")
        log.debug(f"Speed test download: {dl_mbps:.2f} Mbps")

        # ── Upload ────────────────────────────────────────────────────────
        print("    Testing upload...", end="", flush=True)
        ul_bps  = st.upload()
        ul_mbps = ul_bps / 1_000_000
        print(f"  {ul_mbps:.2f} Mbps")
        log.debug(f"Speed test upload: {ul_mbps:.2f} Mbps")

        # ── Collect results ───────────────────────────────────────────────
        results  = st.results
        ping_ms  = results.ping
        srv      = results.server
        name     = f"{srv.get('sponsor', 'Unknown')} ({srv.get('name', '?')}, {srv.get('country', '?')})"
        host     = srv.get("host", "unknown")
        dist_km  = float(srv.get("d", 0))

        elapsed = time.time() - start

        # Scale bars relative to the faster of the two speeds
        max_mbps = max(dl_mbps, ul_mbps, 1.0)

        _print_box(name, host, dist_km, ping_ms, dl_mbps, ul_mbps, max_mbps)
        print(f"\n[✓] Speed test completed in {elapsed:.1f}s\n")

    # ── Error handling ────────────────────────────────────────────────────
    except _st_mod.ConfigRetrievalError:
        print("\n[!] Could not fetch speedtest configuration.")
        print("    Check your internet connection and try again.")
        log.error("Speed test: ConfigRetrievalError")
        sys.exit(1)

    except _st_mod.SpeedtestBestServerFailure:
        print("\n[!] Could not find a suitable speedtest server.")
        print("    Try specifying one with --speed-server <ID>.")
        log.error("Speed test: SpeedtestBestServerFailure")
        sys.exit(1)

    except _st_mod.SpeedtestHTTPError as exc:
        print(f"\n[!] HTTP error during speed test: {exc}")
        log.error(f"Speed test: SpeedtestHTTPError: {exc}")
        sys.exit(1)

    except Exception as exc:
        print(f"\n[!] Speed test failed: {exc}")
        log.error(f"Speed test: unexpected error: {exc}", exc_info=True)
        sys.exit(1)
