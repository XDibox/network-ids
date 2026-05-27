# Network Intrusion Detection System (IDS)

A real-time network IDS written in Python that combines **signature-based** and **anomaly-based** detection engines to identify malicious traffic patterns.

Built as a cybersecurity portfolio project demonstrating packet analysis, statistical baselining, and multi-layered threat detection.

---

## Architecture

```
IDS/
├── IDS.py              # Entry point & CLI
├── config.py           # Thresholds, rules & whitelist
├── report.py           # Alert log report generator
├── core/
│   ├── alert.py        # Alert manager (console + log + Windows notifications)
│   ├── sniffer.py      # Threaded packet capture (scapy)
│   └── whitelist.py    # IP/CIDR whitelist engine
└── engines/
    ├── signature.py    # Rule-based detection engine
    └── anomaly.py      # Statistical baseline + deviation engine
```

---

## Detection Capabilities

### Signature Engine
| Attack | Severity | Method |
|---|---|---|
| Port Scan | HIGH | 15+ unique ports in 10s per source IP |
| SYN Flood | CRITICAL | 200+ SYN packets in 5s |
| ICMP Flood | HIGH | 100+ echo requests in 5s |
| Brute Force | HIGH | 10+ connections in 30s on SSH/FTP/RDP/Telnet |
| NULL Scan | MEDIUM | TCP packet with no flags |
| XMAS Scan | MEDIUM | TCP FIN+PSH+URG flags |
| FIN Scan | LOW | TCP FIN-only flag |
| ARP Spoofing | CRITICAL | IP→MAC table change detected |
| DNS Amplification | HIGH | DNS response > 3000 bytes |
| DNS ANY Query | MEDIUM | DNS type ANY — amplification vector |
| OS Fingerprinting | MEDIUM | Nmap OS probes, low-TTL packets |
| Suspicious Ports | HIGH | Metasploit, Back Orifice, NetBus, etc. |
| SQL Injection | HIGH | Pattern match in HTTP payload |
| XSS / LFI / RCE | HIGH | Pattern match in HTTP payload |

### Anomaly Engine
| Detection | Severity | Method |
|---|---|---|
| Traffic Anomaly | HIGH | Packet rate > 3× statistical baseline |
| IP Sweep | MEDIUM | 30+ new IPs per minute |
| Port Diversity | MEDIUM | 20+ unique ports per IP in 60s |
| Protocol Anomaly | MEDIUM | Protocol ratio > 3× baseline distribution |

---

## Requirements

- Python 3.10+
- Linux / WSL (Kali, Ubuntu, Debian)
- Root / sudo privileges (required for raw packet capture)

### Dependencies
```
scapy>=2.5.0
colorama>=0.4.6
```

---

## Installation

### WSL / Linux

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/network-ids.git
cd network-ids

# Create virtual environment (use Linux filesystem, not /mnt/c)
python3 -m venv ~/venv-ids
source ~/venv-ids/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Windows (native)

1. Install [Npcap](https://npcap.com) — enable **WinPcap API-compatible mode**
2. Install dependencies: `pip install -r requirements.txt`
3. Run PowerShell as Administrator

---

## Usage

```bash
# List available network interfaces
sudo ~/venv-ids/bin/python3 IDS.py --list-interfaces

# Start IDS (auto-detect interface, 30s baseline)
sudo ~/venv-ids/bin/python3 IDS.py

# Specify interface and baseline window
sudo ~/venv-ids/bin/python3 IDS.py -i eth0 --baseline 60

# Custom log file
sudo ~/venv-ids/bin/python3 IDS.py -i eth0 --log /var/log/ids.log
```

### Run as a systemd service (persistent)

```bash
sudo cp ids.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ids
sudo systemctl start ids

# View live logs
sudo journalctl -u ids -f
```

---

## Alert Report

Generate a structured report from the alert log:

```bash
# Full report
python3 report.py

# Filter by date
python3 report.py --since 2026-05-26

# Export to plain text
python3 report.py --export report.txt
```

Sample output:
```
════════════════════════════════════════════════════════════════
  IDS ALERT REPORT  |  2026-05-26 22:29  →  2026-05-26 22:35
════════════════════════════════════════════════════════════════

  SEVERITY SUMMARY
  ────────────────────────────────────────────────────────────────
  CRITICAL    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░     3  (4.9%)
  HIGH        ████████████████████████░░░░░░    61  (83.6%)
  MEDIUM      ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░     1  (1.4%)
```

---

## Whitelist

Add trusted IPs or subnets in `config.py` to suppress false positives:

```python
WHITELIST = {
    '192.168.1.1',   # gateway
    '192.168.1.100', # trusted host
}

WHITELIST_NETWORKS = [
    '10.0.0.0/8',
]
```

---

## Testing

```bash
# Port scan detection
nmap -sS <target_ip>

# OS fingerprinting detection
sudo nmap -O <target_ip>

# ICMP flood detection
sudo ping -f -c 200 <target_ip>

# SYN flood detection
sudo hping3 -S --flood -p 80 <target_ip>

# ARP spoofing detection (via crafted packet)
sudo python3 -c "
from scapy.all import sendp, ARP, Ether
pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, psrc='192.168.1.1', hwsrc='aa:bb:cc:dd:ee:ff')
sendp(pkt, iface='eth0', count=3)
"
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
