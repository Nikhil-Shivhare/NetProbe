
# 🔍 NetProbe — Python Network Reconnaissance Tool

NetProbe is a Python-based network reconnaissance tool that performs **ARP-based host discovery** and **TTL-based OS fingerprinting** to enumerate live devices on a local network. It displays **IP address, MAC address, vendor name, and estimated operating system** in a clean tabular format.  
This tool is designed for **educational use and permissioned internal security audits** only.

---

## ✨ Features

- ✅ ARP-based **live host discovery**
- ✅ Displays:
  - IP Address  
  - MAC Address  
  - Vendor Name  
  - Operating System (TTL-based detection)
- ✅ **TTL-based OS fingerprinting**
  - Linux / macOS → TTL ≈ 64  
  - Windows → TTL ≈ 128  
  - Network Devices → TTL ≈ 255
- ✅ Command-line interface (CLI)
- ✅ Clean tabular output using PrettyTable
- ✅ Works on CIDR ranges and single IPs
- ✅ Permissioned internal network scanning

---

## 🛠️ Technologies Used

- **Python 3**
- **Scapy** – Packet crafting & ARP/ICMP scanning
- **PrettyTable** – Table formatting
- **mac-vendor-lookup** – MAC vendor resolution
- **Argparse** – CLI argument parsing


## 📦 Installation

Clone or download this project and go into the directory:

### 1️⃣ Clone the Repository
```bash
pip install scapy prettytable mac-vendor-lookup

