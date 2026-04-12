
# 🔍 NetProbe — Python Network Reconnaissance Tool

NetProbe is a Python-based network reconnaissance tool that performs **ARP-based host discovery**, **TTL-based OS fingerprinting**, and **TCP SYN port scanning** to enumerate live devices on a local network.  
This tool is designed for **educational use and permissioned internal security audits** only.

---

## ✨ Features

- ✅ ARP-based **live host discovery**
- ✅ **TTL-based OS fingerprinting**
  - Linux / macOS → TTL ≈ 64
  - Windows → TTL ≈ 128
  - Network Devices → TTL ≈ 255
- ✅ **TCP SYN port scanner** – detects 101 common services (SSH, HTTP, RDP, MySQL, Redis …)
- ✅ **Multi-threaded scanning** – concurrent OS detection & port probing
- ✅ **tqdm progress bars** – real-time scan progress per phase
- ✅ **Verbose logging** – `--verbose` flag enables detailed debug output via Python `logging`
- ✅ Clean tabular output using PrettyTable
- ✅ Works on CIDR ranges and single IPs
- ✅ Displays: IP · MAC · Vendor · OS (TTL) · Open Ports

---

## 🛠️ Technologies Used

- **Python 3**
- **Scapy** – Packet crafting, ARP broadcast, ICMP & TCP SYN scanning
- **PrettyTable** – Table formatting
- **mac-vendor-lookup** – MAC → vendor name resolution
- **tqdm** – Progress bars
- **logging** – Structured debug/info/warning output
- **concurrent.futures** – Thread pool for parallel scanning
- **Argparse** – CLI argument parsing

---

## 📦 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/Nikhil-Shivhare/NetProbe.git
cd NetProbe
```

### 2️⃣ Install Dependencies
```bash
pip install scapy prettytable mac-vendor-lookup tqdm
```

---

## 🚀 Usage

> **Requires `sudo`** — raw socket access needs root privileges.

```bash
sudo python3 Network_scanner.py --h <target> [options]
```

### Options

| Flag | Short | Default | Description |
|---|---|---|---|
| `--h` | | *required* | Hosts or CIDR ranges to scan |
| `--threads` | `-t` | `10` | Thread count for all concurrent tasks |
| `--ports` | `-p` | 101 common ports | Custom port list to scan |
| `--no-ports` | | `False` | Skip port scanning (host + OS only) |
| `--verbose` | `-v` | `False` | Enable debug-level logging |

### Examples

```bash
# Scan a full subnet (default 23 ports, 10 threads)
sudo python3 Network_scanner.py --h 192.168.1.0/24

# Scan with 20 threads and custom ports
sudo python3 Network_scanner.py --h 192.168.1.0/24 --threads 20 --ports 22 80 443 3306

# Discovery only, skip port scan
sudo python3 Network_scanner.py --h 192.168.1.0/24 --no-ports

# Verbose mode (debug logs to terminal)
sudo python3 Network_scanner.py --h 192.168.1.5 --verbose

# Scan multiple targets
sudo python3 Network_scanner.py --h 192.168.1.1 10.0.0.0/24
```

### Sample Output

```
[*] Scanning target: 192.168.1.0/24
[*] OS fingerprinting 4 host(s)...
  OS Detect |████████████████| 4/4 [00:01]
[*] Port scanning 4 host(s) × 23 ports...
  Port Scan  |████████████████| 92/92 [00:03, 27.4 probe/s]
[✓] Scan completed in 4.82s — 4 host(s) found

+--------------+-------------------+------------+------------------+---------------------------+
| IP           | MAC               | VENDOR     | OS (TTL)         | OPEN PORTS                |
+--------------+-------------------+------------+------------------+---------------------------+
| 192.168.1.1  | aa:bb:cc:11:22:33 | TP-Link    | Net Device [254] | 80/HTTP, 443/HTTPS        |
| 192.168.1.5  | dd:ee:ff:44:55:66 | Apple Inc  | Linux/macOS [63] | 22/SSH                    |
| 192.168.1.12 | 11:22:33:44:55:66 | Intel Corp | Windows [127]    | 135/RPC, 445/SMB, 3389/RDP|
| 192.168.1.20 | 77:88:99:aa:bb:cc | Raspberry  | Linux/macOS [64] | 22/SSH, 80/HTTP, 6379/Redis|
+--------------+-------------------+------------+------------------+---------------------------+
```

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational purposes and authorized internal network audits**.  
**Do not use NetProbe on networks you do not own or have explicit permission to test.**  
Unauthorized scanning may violate local laws.
