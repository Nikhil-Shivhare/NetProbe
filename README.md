# NetProbe
A simple Python-based ARP network scanner that discovers live hosts on your local network and shows their IP address, MAC address, and vendor information in a clean table.

✨ Features
Scans one or multiple IPs / subnets using ARP
Detects live hosts on the local network
Displays results in a formatted table (IP, MAC, VENDOR)
Automatically looks up MAC address vendors
Simple CLI interface using command-line arguments

🛠️ Technologies Used
Python 3
Scapy – for crafting and sending ARP packets
PrettyTable – for displaying results in a table
mac-vendor-lookup – for resolving MAC address vendors
argparse – for command-line argument parsing

🔧 Installation
Clone or download this project and go into the directory:
Install dependencies :
pip install scapy prettytable mac-vendor-lookup

▶️ Usage
The script is Network_scanner.py. It takes one or more hosts/subnets as input using the --h argument.

Note: Run with sudo or as root, because Scapy requires elevated privileges for packet sending.
Basic syntax
sudo python3 Network_scanner.py --h <host1> <host2> ...
