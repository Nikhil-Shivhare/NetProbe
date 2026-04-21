# output.py — Scan result formatting and display

from prettytable import PrettyTable
from mac_vendor_lookup import MacLookup


def print_results(alive, os_info, port_info, skip_ports=False):
    """Print a formatted PrettyTable of scan results.

    Args:
        alive:      dict  { ip: mac }
        os_info:    dict  { ip: "OS [TTL:x WIN:y] (confidence)" }
        port_info:  dict  { ip: ["22/SSH", ...] }
        skip_ports: bool  whether to hide the OPEN PORTS column
    """
    headers = ["IP", "MAC", "VENDOR", "OS (TTL)"]
    if not skip_ports:
        headers.append("OPEN PORTS")

    table           = PrettyTable(headers)
    table.max_width = 50
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

        table.add_row(row)

    print(table)
