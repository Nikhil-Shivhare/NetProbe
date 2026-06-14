# output.py — Scan result formatting and display

from __future__ import annotations

from typing import Dict, Optional
from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup


def _format_banner_cell(ip: str, port_info: dict, banner_info: dict) -> str:
    """Build the multi-line BANNERS cell for one host.

    Each open port produces one line:  ``22/SSH  → OpenSSH 9.2p1``
    When no version is found the raw banner (truncated) is shown instead.
    Hosts with no open ports get an em-dash.
    """
    ports = port_info.get(ip, [])
    if not ports:
        return "\u2014"

    host_banners = banner_info.get(ip, {})
    lines = []
    for port_str in ports:
        result = host_banners.get(port_str)
        if result is None:
            lines.append(f"{port_str:12s}  \u2192 (no data)")
            continue

        if result.version:
            detail = result.version
        elif result.raw_banner and not result.raw_banner.startswith("["):
            # truncate long raw banners to keep the table tidy
            detail = result.raw_banner[:60].replace("\n", " ")
        else:
            detail = result.raw_banner or "(no response)"

        lines.append(f"{port_str:12s}  \u2192 {detail}")

    return "\n".join(lines) if lines else "\u2014"


def print_results(
    alive: dict,
    os_info: dict,
    port_info: dict,
    skip_ports: bool = False,
    banner_info: Optional[Dict] = None,
) -> None:
    """Print a formatted PrettyTable of scan results.

    Args:
        alive:       dict  { ip: mac }
        os_info:     dict  { ip: "OS [TTL:x WIN:y] (confidence)" }
        port_info:   dict  { ip: ["22/SSH", ...] }
        skip_ports:  bool  whether to hide the OPEN PORTS column
        banner_info: dict  { ip: { "22/SSH": BannerResult, ... } } or None.
                     When not None a BANNERS column is appended to the table.
    """
    show_banners = banner_info is not None and not skip_ports

    headers = ["IP", "MAC", "VENDOR", "OS (TTL)"]
    if not skip_ports:
        headers.append("OPEN PORTS")
    if show_banners:
        headers.append("BANNERS")

    table           = PrettyTable(headers)
    table.max_width = 55
    table.align     = "l"

    for ip, mac in alive.items():
        try:
            vendor = MacLookup().lookup(mac)
        except Exception:
            vendor = "NA"

        os_data = os_info.get(ip, "Unknown")
        row     = [ip, mac, vendor, os_data]

        if not skip_ports:
            ports     = port_info.get(ip, [])
            ports_str = ", ".join(ports) if ports else "none"
            row.append(ports_str)

        if show_banners:
            row.append(_format_banner_cell(ip, port_info, banner_info))

        table.add_row(row)

    print(table)

