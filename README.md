<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&pause=1000&color=00D4FF&center=true&vCenter=true&width=600&lines=🔍+NetProbe;Python+Network+Reconnaissance+Tool" alt="NetProbe" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Powered%20by-Scapy-009688?style=for-the-badge)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/Nikhil-Shivhare/NetProbe)
[![Requires Root](https://img.shields.io/badge/Requires-sudo-ef4444?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/Nikhil-Shivhare/NetProbe)

<br/>

> **A fast, modular Python network reconnaissance tool.**  
> Discover live hosts · Fingerprint operating systems · Scan an extended 501-port list · Grab service banners — all in one command.

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [OS Fingerprinting](#-os-fingerprinting)
- [Project Structure](#️-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
  - [Direct-run usage](#-direct-run-usage)
  - [Current limitations](#-current-limitations)
- [Sample Output](#-sample-output)
- [Port Coverage](#-port-coverage)
- [Technologies](#️-technologies)
- [Roadmap](#️-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Testing](#-testing)
- [Development Setup](#-development-setup)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#️-disclaimer)

---

## 🧭 Overview

**NetProbe** is a network reconnaissance toolkit built with Python and Scapy. It is designed for **authorized security audits and educational use**, enabling network administrators and security researchers to quickly enumerate live devices, identify operating systems, and discover exposed services on a local network.

It runs in up to **four phases**:

```
Phase 1 → ARP broadcast          Discover all live hosts on the network
Phase 2 → ICMP + TCP SYN probe   Fingerprint each host's OS
Phase 3 → TCP SYN port scan      Identify open services on each host
Phase 4 → Banner grabbing        Extract service version strings (opt-in: --banners)
```

OS and port work inside each phase is threaded; phases run sequentially after ARP discovery.

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🖧 **ARP Host Discovery** | Ethernet broadcast scan to find all live devices on a subnet |
| 🧬 **Dual OS Fingerprinting** | ICMP TTL + TCP Window Size — two probes, one verdict with confidence score |
| 🔎 **Linux vs macOS Detection** | Heuristic TTL + TCP window-size detection; separates Linux/macOS when the signals align, but conflicts are reported with medium confidence |
| 🔒 **TCP SYN Port Scanner** | Stealthy half-open scan — sends SYN, reads SYN-ACK, resets immediately |
| 📦 **101 to 501 Ports** | 101 default common ports, or an extended 501-port list with `--all-ports` |
| 🏷️ **Banner Grabbing** | Optional Phase 4: grab service version strings via `--banners` (SSH, FTP, SMTP, HTTP/S, POP3, IMAP + generic fallback) |
| ⚡ **Multi-threaded** | Configurable thread pool (`--threads`) for OS detection, port probing, and banner grabbing |
| 🌐 **Internet Speed Test** | Standalone `--speed-test` mode: measures download/upload Mbps and ping to an Ookla server — independent of LAN scanning |
| 📊 **Live Progress Bars** | Per-phase `tqdm` bars showing count, elapsed time, and probe rate |
| 🗂️ **Modular Package** | Clean `netprobe/` package — each concern in its own testable module |
| 🖥️ **Rich CLI** | Full argparse interface with ASCII banner, usage examples, and `--help` |
| 📝 **Structured Debug Logging** | `--verbose` enables timestamped structured DEBUG logging for probe events |
| 🔁 **Multi-target Support** | Scan multiple IPs and CIDR ranges in a single command |
| 🛡️ **Graceful Error Recovery** | Skips unreachable targets with a warning — never aborts the full scan |
| 📦 **pip Installable** | `pip install .` registers a global `netprobe` command via `pyproject.toml` |

---

## 🧬 OS Fingerprinting

NetProbe sends **two independent probes** per host and combines their signals into a single confidence-scored verdict.

```
┌─────────────────────────────────────────────────────────────────┐
│  Probe 1 → ICMP Echo Request   → inspect reply TTL              │
│  Probe 2 → TCP SYN to port 80  → inspect SYN-ACK window size   │
└─────────────────────────────────────────────────────────────────┘

  TTL ≈  64  +  Window ≈ 29200  ──→  Linux       (high confidence)
  TTL ≈  64  +  Window ≈ 65535  ──→  macOS       (high confidence)
  TTL ≈ 128  +  Window ≈ 65535  ──→  Windows     (high confidence)
  TTL ≈ 255  +  any             ──→  Net Device  (high confidence)
  Only one probe responds        ──→  OS family   (medium confidence)
  Both probes fail               ──→  Unknown     (low confidence)
```

Output format per host: `Linux [TTL:64 WIN:29200] (high)`

---

## 🏗️ Project Structure

```
NetProbe/
├── Network_scanner.py         # Direct CLI wrapper for running without installing
├── README.md                  # Project documentation
├── pyproject.toml             # Python package metadata and `netprobe` console script
├── requirements.txt           # Runtime dependency list
├── netprobe/
│   ├── __init__.py            # Package init — exports NetworkScanner v2.0.0
│   ├── scanner.py             # NetworkScanner orchestrator + installed `netprobe` CLI entry point
│   ├── validator.py           # CLI input validation for targets, ports, and threads
│   ├── os_fingerprint.py      # Dual-probe OS detection using ICMP TTL + TCP window size
│   ├── port_scanner.py        # TCP SYN half-open port scanner
│   ├── banner_grabber.py      # Phase 4 — service banner & version extraction (stdlib only)
│   ├── speed_test.py          # Standalone internet speed test (speedtest-cli wrapper)
│   ├── output.py              # PrettyTable result formatter with MAC vendor lookup
│   └── ports.py               # Common + extended TCP port/service mappings
```

---

## 📦 Installation

> **⚠️ Root Required** — NetProbe uses raw sockets (Scapy) which require `sudo`.

### Option 1 — pip install *(recommended)*

```bash
git clone https://github.com/Nikhil-Shivhare/NetProbe.git
cd NetProbe
pip install .
```

After installation, run from anywhere on your system:

```bash
sudo netprobe -H 192.168.1.0/24
```

### Option 2 — Run directly without installing

```bash
git clone https://github.com/Nikhil-Shivhare/NetProbe.git
cd NetProbe
pip install -r requirements.txt
sudo python3 Network_scanner.py --h 192.168.1.0/24
```

This runs the wrapper script directly and does not require building or installing the package.

---

## 🚀 Usage

```
sudo netprobe -H <target> [options]
```

### Direct-run usage

If you did not install the package, replace `netprobe` with `python3 Network_scanner.py`:

```bash
sudo python3 Network_scanner.py --h 192.168.1.0/24
```

### CLI Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `-H`/`--host TARGET [...]` | `-H` | *required* | One or more host IPs or CIDR ranges |
| `--threads N` | `-t` | `10` | Thread count for concurrent tasks |
| `--ports PORT [...]` | `-p` | 101 common ports | Custom port list to scan |
| `--all-ports` | `-A` | `False` | Scan the extended 501-port list |
| `--no-ports` | `-n` | `False` | Skip port scan — discovery + OS only |
| `--banners` | `-b` | `False` | Enable Phase 4: grab service banners from all open ports |
| `--banner-timeout SEC` | | `4.0` | Per-connection timeout for banner grabs in seconds |
| `--arp-timeout SEC` | | `1.0` | ARP broadcast wait time in seconds |
| `-o`/`--output FILE` | | `None` | Save results to a text file |
| `--speed-test` | `-s` | `False` | Run an internet speed test and exit (no target needed) |
| `--speed-server ID` | | auto | Ookla server ID to use; omit to auto-select the fastest server |
| `--verbose` | `-v` | `False` | Enable timestamped structured DEBUG logging for probe events |

### Examples

```bash
# Scan an entire subnet (default: 101 ports, 10 threads)
sudo netprobe -H 192.168.1.0/24

# Scan a single host
sudo netprobe -H 192.168.1.1

# Fast mode — ARP discovery + OS fingerprinting only
sudo netprobe -H 192.168.1.0/24 --no-ports

# Scan with more threads and a custom port list
sudo netprobe -H 192.168.1.0/24 --threads 30 --ports 22 80 443 3306 5432

# Banner grabbing — grab service versions from all open ports
sudo netprobe -H 192.168.1.0/24 --banners

# Banner grabbing on specific ports only
sudo netprobe -H 192.168.1.1 --ports 22 80 443 --banners

# Increase banner timeout for slow/embedded devices (default 4s)
sudo netprobe -H 192.168.1.0/24 --banners --banner-timeout 6

# Internet speed test — measures THIS machine's connection, not LAN hosts
netprobe --speed-test

# Speed test with a specific Ookla server ID
netprobe --speed-test --speed-server 21541

# Verbose mode — enable structured DEBUG logging for probe events
sudo netprobe -H 192.168.1.5 --verbose

# Scan multiple targets in one run
sudo netprobe -H 192.168.1.0/24 10.0.0.1 172.16.0.0/24
```

### Sample Speed Test Output

```
[*] Running Internet Speed Test...
    Finding best server...  Jio (Mumbai, IN)  ✓
    Testing download...  87.23 Mbps
    Testing upload...    21.05 Mbps

  ┌─────────────────────────────────────────────────┐
  │  NetProbe  ·  Internet Speed Test               │
  ├─────────────────────────────────────────────────┤
  │  Server    :  Jio (Mumbai, IN)                  │
  │  Host      :  speedtest5.jio.com:8080           │
  │  Distance  :  12.4 km                           │
  │  Ping      :  18.4 ms                           │
  │  Download  :  87.23 Mbps  ▓▓▓▓▓░░░░░░░          │
  │  Upload    :  21.05 Mbps  ▓▓░░░░░░░░░░          │
  └─────────────────────────────────────────────────┘

[✓] Speed test completed in 14.2s
```

### Current limitations

- Requires `sudo`/root because Scapy raw sockets are used for ARP, ICMP, and TCP SYN probes.
- Supports IPv4 IP addresses and CIDR ranges only; host ranges such as `192.168.1.1-10` are not supported.
- Port scanning is TCP SYN only; UDP scans are not supported.
- `--banners` requires port scanning to be active; it prints a warning and is skipped when combined with `--no-ports`.
- Banner grabbing uses a 4.0-second per-connection timeout; firewalled ports may appear as `[timeout]`.
- `--all-ports` scans the 501 configured ports, not every TCP port from 1–65535.
- `--verbose` enables structured DEBUG logging for probe events.

---

## 📋 Sample Output

**Without `--banners`** (default):
```
[*] Scanning target: 192.168.1.0/24
[*] OS fingerprinting 4 host(s) (TTL + TCP Window)...
  OS Detect |████████████████████████| 4/4 [00:02]
[*] Port scanning 4 host(s) × 101 ports...
  Port Scan  |████████████████████████| 404/404 [00:12, 33.6 probe/s]
[✓] Scan completed in 14.82s — 4 host(s) found

+--------------+-------------------+------------+--------------------------------------------+------------------------------+
| IP           | MAC               | VENDOR     | OS (TTL)                                   | OPEN PORTS                   |
+--------------+-------------------+------------+--------------------------------------------+------------------------------+
| 192.168.1.1  | aa:bb:cc:11:22:33 | TP-Link    | Net Device [TTL:254 WIN:4128] (high)       | 80/HTTP, 443/HTTPS           |
| 192.168.1.5  | dd:ee:ff:44:55:66 | Apple Inc  | macOS [TTL:64 WIN:65535] (high)            | 22/SSH                       |
| 192.168.1.12 | 11:22:33:44:55:66 | Intel Corp | Windows [TTL:128 WIN:65535] (high)         | 135/RPC, 445/SMB, 3389/RDP   |
| 192.168.1.20 | 77:88:99:aa:bb:cc | Raspberry  | Linux [TTL:64 WIN:29200] (high)            | 22/SSH, 80/HTTP, 6379/Redis  |
+--------------+-------------------+------------+--------------------------------------------+------------------------------+
```

**With `--banners`** (Phase 4 enabled):
```
[*] Scanning target: 192.168.1.0/24
[*] OS fingerprinting 4 host(s) (TTL + TCP Window)...
  OS Detect |████████████████████████| 4/4 [00:02]
[*] Port scanning 4 host(s) × 101 ports...
  Port Scan  |████████████████████████| 404/404 [00:12, 33.6 probe/s]
[*] Banner grabbing 3 host(s) with open ports...
[✓] Scan completed in 22.14s — 4 host(s) found

+--------------+-------------------+------------+------------------------------+------------------------------+----------------------------------+
| IP           | MAC               | VENDOR     | OS (TTL)                     | OPEN PORTS                   | BANNERS                          |
+--------------+-------------------+------------+------------------------------+------------------------------+----------------------------------+
| 192.168.1.1  | aa:bb:cc:11:22:33 | TP-Link    | Net Device [TTL:254 ...](high)| 80/HTTP, 443/HTTPS          | 80/HTTP      → nginx/1.24.0      |
|              |                   |            |                              |                              | 443/HTTPS    → nginx/1.24.0      |
| 192.168.1.5  | dd:ee:ff:44:55:66 | Apple Inc  | macOS [TTL:64 WIN:65535](high)| 22/SSH                      | 22/SSH       → OpenSSH 9.2p1     |
| 192.168.1.20 | 77:88:99:aa:bb:cc | Raspberry  | Linux [TTL:64 WIN:29200](high)| 22/SSH, 80/HTTP             | 22/SSH       → OpenSSH 8.9p1     |
|              |                   |            |                              |                              | 80/HTTP      → Apache/2.4.57     |
+--------------+-------------------+------------+------------------------------+------------------------------+----------------------------------+
```

### Output Columns

| Column | Description |
|---|---|
| **IP** | IPv4 address of the live host |
| **MAC** | Hardware (MAC) address from the ARP reply |
| **VENDOR** | NIC manufacturer resolved from the MAC OUI prefix |
| **OS (TTL)** | OS verdict — `Name [TTL:x WIN:y] (confidence)` |
| **OPEN PORTS** | Sorted open ports — `port/service`, e.g. `22/SSH, 80/HTTP` |
| **BANNERS** | *(only with `--banners`)* One line per open port: `22/SSH → OpenSSH 9.2p1` |

---

## 🗄️ Port Coverage

NetProbe scans **101 ports** across 12 service categories by default (expandable to **501 ports** via `--all-ports`):

| Category | Examples |
|---|---|
| File Transfer | FTP (20/21), SFTP (115), FTPS (989/990), TFTP (69) |
| Remote Access | SSH (22), Telnet (23), RDP (3389), VNC (5900–5902) |
| Mail | SMTP (25), POP3 (110), IMAP (143), SMTPS (465) |
| Web | HTTP (80), HTTPS (443), HTTP/HTTPS Alt (8080/8443/8888) |
| DNS & Directory | DNS (53), LDAP (389), Kerberos (88) |
| Windows / SMB | RPC (135), NetBIOS (137–139), SMB (445) |
| Databases | MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), Elasticsearch (9200) |
| Message Queues | Kafka (9092), RabbitMQ (5672/15672), MQTT (1883), ActiveMQ (61616) |
| DevOps / Infra | Docker (2375), Kubernetes (6443), etcd (2379), Consul (8500) |
| Monitoring | SNMP (161), Grafana (3000), Prometheus (9090), Kibana (5601) |
| Security | OpenVPN (1194), PPTP (1723), IKE (500), SOCKS (1080) |
| Misc | NTP (123), IRC (194/6667), Git (9418), Memcached (11211) |

> Custom ports can override the default list with `--ports 22 80 443 ...` or use `--all-ports` to scan the extended 501-port list.

---

## 🛠️ Technologies

| Library | Role |
|---|---|
| [Scapy](https://scapy.net/) | Packet crafting — ARP broadcast, ICMP ping, TCP SYN |
| [PrettyTable](https://pypi.org/project/prettytable/) | Formatted ASCII table rendering |
| [mac-vendor-lookup](https://pypi.org/project/mac-vendor-lookup/) | MAC OUI → manufacturer name resolution |
| [tqdm](https://tqdm.github.io/) | Real-time per-phase progress bars |
| `concurrent.futures` | Thread pool executor for parallel scanning |
| `argparse` | CLI argument parsing with formatted help output |
| `logging` | Structured WARNING/DEBUG log output |

---

## 🗺️ Roadmap

### ✅ Completed
- [x] ARP host discovery
- [x] TTL-based OS fingerprinting
- [x] TCP Window Size OS fingerprinting
- [x] Combined OS confidence scoring (`high` / `medium` / `low`)
- [x] TCP SYN port scanner (101 default, 501 via `--all-ports`)
- [x] Multi-threaded scanning with live progress bars
- [x] Modular `netprobe/` package structure
- [x] pip-installable with global `netprobe` command
- [x] Graceful error recovery for unreachable targets
- [x] Service banner grabbing — SSH, FTP, SMTP, HTTP/S, POP3, IMAP (`--banners`)

### 🔜 Planned
- [ ] JSON / CSV / HTML scan export (`--output report.json`)
- [ ] Colorized terminal output with confidence indicators
- [ ] Scan summary block (total hosts, ports, time)
- [ ] UDP service scan (`--udp`)
- [ ] Rate limiting / stealth mode (`--rate`, `--stealth`)

---

## 🤝 Contributing

Contributions are welcome! To keep the project maintainable:

1. Fork the repository and create a feature branch from `main`.
2. Follow the existing code style and module conventions.
3. Add tests for any new functionality.
4. Open a pull request with a clear description of the change and any related issues.

Please report bugs or feature requests via [GitHub Issues](https://github.com/Nikhil-Shivhare/NetProbe/issues).

---

## 📄 License

This project is released under the [MIT License](LICENSE).

---

## 🧪 Testing

```bash
pip install -r requirements.txt
python3 -m pytest tests/
```

---

## 🛠️ Development Setup

```bash
git clone https://github.com/Nikhil-Shivhare/NetProbe.git
cd NetProbe
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## 🔧 Troubleshooting

| Symptom | Solution |
|---|---|
| `PermissionError` / `OSError` on raw sockets | Run with `sudo`. Scapy requires root for ARP, ICMP, and TCP SYN probes. |
| `ImportError: No module named 'speedtest_cli'` | Install the optional dependency: `pip install speedtest-cli` |
| `SSL error` during banner grabbing | Some services use legacy TLS. NetProbe uses a permissive SSL context for HTTPS, but firewalls may still block probes. Try increasing `--banner-timeout`. |
| `No hosts are up` | Ensure you are on the same broadcast domain. ARP does not traverse routers. Use a CIDR range that matches your local subnet. |
| `Server not found` during `--speed-test` | The Ookla server ID may be invalid or offline. Omit `--speed-server` to auto-select the fastest server. |

---

## ⚠️ Disclaimer

This tool is provided for **educational purposes and authorized security auditing only**.

> **Do not run NetProbe against networks you do not own or have explicit written permission to test.**  
> Unauthorized network scanning may violate the Computer Fraud and Abuse Act (CFAA), GDPR, or other applicable laws in your jurisdiction.  
> The author assumes no liability for misuse of this tool.

---

<div align="center">

**If this project helped you, consider giving it a ⭐ on GitHub!**

Made with ❤️ by [Nikhil Shivhare](https://github.com/Nikhil-Shivhare)

</div>
