<div align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&pause=1000&color=00D4FF&center=true&vCenter=true&width=600&lines=🔍+NetProbe;Python+Network+Reconnaissance+Tool" alt="NetProbe" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Powered%20by-Scapy-009688?style=for-the-badge)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/Nikhil-Shivhare/NetProbe)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Requires Root](https://img.shields.io/badge/Requires-sudo-ef4444?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/Nikhil-Shivhare/NetProbe)

<br/>

> **A fast, modular Python network reconnaissance tool.**  
> Discover live hosts · Fingerprint operating systems · Probe 101 common ports — all in one command.

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [OS Fingerprinting](#-os-fingerprinting)
- [Project Structure](#️-project-structure)
- [Installation](#-installation)
- [Usage](#-usage)
- [Sample Output](#-sample-output)
- [Port Coverage](#-port-coverage)
- [Technologies](#️-technologies)
- [Roadmap](#️-roadmap)
- [Disclaimer](#️-disclaimer)

---

## 🧭 Overview

**NetProbe** is a network reconnaissance toolkit built with Python and Scapy. It is designed for **authorized security audits and educational use**, enabling network administrators and security researchers to quickly enumerate live devices, identify operating systems, and discover exposed services on a local network.

It runs in **three phases**:

```
Phase 1 → ARP broadcast          Discover all live hosts on the network
Phase 2 → ICMP + TCP SYN probe   Fingerprint each host's OS
Phase 3 → TCP SYN port scan      Identify open services on each host
```

All phases run **concurrently** using thread pools, with real-time progress bars and structured logging.

---

## ✨ Features

| Feature | Detail |
|---|---|
| 🖧 **ARP Host Discovery** | Ethernet broadcast scan to find all live devices on a subnet |
| 🧬 **Dual OS Fingerprinting** | ICMP TTL + TCP Window Size — two probes, one verdict with confidence score |
| 🔎 **Linux vs macOS Detection** | Correctly separates Linux (WIN≈29200) from macOS (WIN≈65535) — both have TTL≈64 |
| 🔒 **TCP SYN Port Scanner** | Stealthy half-open scan — sends SYN, reads SYN-ACK, resets immediately |
| 📦 **101 Common Ports** | 12 categories: web, databases, mail, remote access, DevOps, monitoring & more |
| ⚡ **Multi-threaded** | Configurable thread pool (`--threads`) for OS detection and port probing |
| 📊 **Live Progress Bars** | Per-phase `tqdm` bars showing count, elapsed time, and probe rate |
| 🗂️ **Modular Package** | Clean `netprobe/` package — each concern in its own testable module |
| 🖥️ **Rich CLI** | Full argparse interface with ASCII banner, usage examples, and `--help` |
| 📝 **Verbose Debug Logging** | `--verbose` flag for timestamped per-packet debug output |
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
├── netprobe/
│   ├── __init__.py          # Package init — exports NetworkScanner v2.0.0
│   ├── scanner.py           # NetworkScanner class + netprobe CLI entry point
│   ├── os_fingerprint.py    # Dual-probe OS detection (TTL + TCP Window)
│   ├── port_scanner.py      # TCP SYN half-open port scanner
│   ├── output.py            # PrettyTable result formatter
│   └── ports.py             # 101 port → service name mappings
├── Network_scanner.py       # Backward-compatible CLI wrapper
├── pyproject.toml           # pip packaging — registers `netprobe` command
├── requirements.txt         # pip dependency list
└── README.md
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
sudo netprobe --h 192.168.1.0/24
```

### Option 2 — Run directly without installing

```bash
git clone https://github.com/Nikhil-Shivhare/NetProbe.git
cd NetProbe
pip install -r requirements.txt
sudo python3 Network_scanner.py --h 192.168.1.0/24
```

---

## 🚀 Usage

```
sudo netprobe --h <target> [options]
```

### CLI Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--h TARGET [...]` | | *required* | One or more host IPs or CIDR ranges |
| `--threads N` | `-t` | `10` | Thread count for concurrent tasks |
| `--ports PORT [...]` | `-p` | 101 common ports | Custom port list to scan |
| `--no-ports` | | `False` | Skip port scan — discovery + OS only |
| `--verbose` | `-v` | `False` | Enable timestamped DEBUG logging |

### Examples

```bash
# Scan an entire subnet (default: 101 ports, 10 threads)
sudo netprobe --h 192.168.1.0/24

# Scan a single host
sudo netprobe --h 192.168.1.1

# Fast mode — ARP discovery + OS fingerprinting only
sudo netprobe --h 192.168.1.0/24 --no-ports

# Scan with more threads and a custom port list
sudo netprobe --h 192.168.1.0/24 --threads 30 --ports 22 80 443 3306 5432

# Verbose mode — see every packet sent and received
sudo netprobe --h 192.168.1.5 --verbose

# Scan multiple targets in one run
sudo netprobe --h 192.168.1.0/24 10.0.0.1 172.16.0.0/24
```

---

## 📋 Sample Output

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

### Output Columns

| Column | Description |
|---|---|
| **IP** | IPv4 address of the live host |
| **MAC** | Hardware (MAC) address from the ARP reply |
| **VENDOR** | NIC manufacturer resolved from the MAC OUI prefix |
| **OS (TTL)** | OS verdict — `Name [TTL:x WIN:y] (confidence)` |
| **OPEN PORTS** | Sorted open ports — `port/service`, e.g. `22/SSH, 80/HTTP` |

---

## 🗄️ Port Coverage

NetProbe scans **101 ports** across 12 service categories by default:

| Category | Examples |
|---|---|
| File Transfer | FTP (20/21), SFTP (115), FTPS (989/990), TFTP (69) |
| Remote Access | SSH (22), Telnet (23), RDP (3389), VNC (5900–5902) |
| Mail | SMTP (25), POP3 (110), IMAP (143), SMTPS (465) |
| Web | HTTP (80), HTTPS (443), HTTP-Alt (8080/8443/8888) |
| DNS & Directory | DNS (53), LDAP (389), Kerberos (88) |
| Windows / SMB | RPC (135), NetBIOS (137–139), SMB (445) |
| Databases | MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379), Elasticsearch (9200) |
| Message Queues | Kafka (9092), RabbitMQ (5672/15672), MQTT (1883), ActiveMQ (61616) |
| DevOps / Infra | Docker (2375), Kubernetes (6443), etcd (2379), Consul (8500) |
| Monitoring | SNMP (161), Grafana (3000), Prometheus (9090), Kibana (5601) |
| Security | OpenVPN (1194), PPTP (1723), IKE (500), SOCKS (1080) |
| Misc | NTP (123), IRC (194/6667), Git (9418), Memcached (11211) |

> Custom ports can override the default list with `--ports 22 80 443 ...`

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
- [x] TCP SYN port scanner (101 ports, 12 categories)
- [x] Multi-threaded scanning with live progress bars
- [x] Modular `netprobe/` package structure
- [x] pip-installable with global `netprobe` command
- [x] Graceful error recovery for unreachable targets

### 🔜 Planned
- [ ] JSON / CSV / HTML scan export (`--output report.json`)
- [ ] Service banner grabbing — SSH, HTTP, SMB (`--banners`)
- [ ] Colorized terminal output with confidence indicators
- [ ] Scan summary block (total hosts, ports, time)
- [ ] UDP service scan (`--udp`)
- [ ] Rate limiting / stealth mode (`--rate`, `--stealth`)

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
