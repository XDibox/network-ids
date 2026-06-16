# Network Intrusion Detection System (IDS)

A real-time network IDS written in Python combining **signature-based** and **anomaly-based** detection engines, threat intelligence enrichment, GeoIP geolocation, automatic PCAP capture, and a live TUI dashboard.

Built as a cybersecurity portfolio project demonstrating packet analysis, statistical baselining, and multi-layered threat detection.

---

## Architecture

```
IDS/
├── IDS.py              # Entry point & CLI
├── config.py           # Thresholds, rules, whitelist & integrations
├── report.py           # Alert log report generator
├── ids.service         # systemd service file
├── core/
│   ├── alert.py        # Alert manager (console + log + Windows toast)
│   ├── dashboard.py    # Live TUI dashboard (rich)
│   ├── geoip.py        # GeoIP engine (ip-api.com / MaxMind)
│   ├── pcap_writer.py  # Automatic PCAP capture on alerts
│   ├── sniffer.py      # Threaded packet capture (scapy)
│   ├── threat_intel.py # Threat intelligence (AbuseIPDB + local feeds)
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
| OS Fingerprinting | MEDIUM | Nmap OS probes, ECN probe, low-TTL packets |
| Suspicious Ports | HIGH | Metasploit (4444), Back Orifice (31337), NetBus, etc. |
| SQL Injection | HIGH | Pattern match in HTTP payload |
| XSS / LFI / RCE | HIGH | Pattern match in HTTP payload |

### Anomaly Engine
| Detection | Severity | Method |
|---|---|---|
| Traffic Anomaly | HIGH | Packet rate > 3× statistical baseline |
| IP Sweep | MEDIUM | 30+ new IPs per minute |
| Port Diversity | MEDIUM | 20+ unique ports per IP in 60s |
| Protocol Anomaly | MEDIUM | Protocol ratio > 3× baseline distribution |

### Threat Intelligence
| Source | Method |
|---|---|
| AbuseIPDB | REST API — alerts on IPs with confidence score ≥ 50% |
| Local feeds | Text files (one IP per line) loaded at startup |
| Static blacklist | Hardcoded IPs in `config.py` |

### GeoIP Enrichment
Every alert includes country, city, ISP, and proxy/hosting detection.
- Default: **ip-api.com** (free, no key required, 45 req/min)
- Optional: **MaxMind GeoLite2** (offline, no rate limit)

---

## Requirements

- Python 3.10+
- Linux (any distro — Arch, Kali, Ubuntu, Debian, Fedora…) or WSL
- Root / sudo privileges (required for raw packet capture)

### Dependencies
```
scapy>=2.5.0
colorama>=0.4.6
rich>=13.0.0
# geoip2>=4.0.0  # Optional: for MaxMind offline database
```

Desktop notifications require `libnotify` (`notify-send`), available in most distros:
```bash
# Arch / EndeavourOS
sudo pacman -S libnotify

# Debian / Ubuntu / Kali
sudo apt install libnotify-bin
```

---

## Installation

### Linux (native)

```bash
# Clone the repository
git clone https://github.com/XDibox/network-ids.git
cd network-ids

# Install dependencies (Arch / EndeavourOS)
sudo pacman -S python-scapy python-rich python-colorama

# Install dependencies (Debian / Ubuntu / Kali)
sudo apt install python3-scapy python3-rich python3-colorama
```

### WSL (Windows Subsystem for Linux)

```bash
git clone https://github.com/XDibox/network-ids.git
cd network-ids
pip install -r requirements.txt
```

The IDS will use a PowerShell-based Windows toast notification as fallback
when `notify-send` is not available. Use the Linux filesystem (`~`),
not `/mnt/c`, for best performance.

---

## Custom Rules (YAML)

Detection rules are defined in YAML files inside `rules/`. You can tune thresholds or add new entries without touching any Python code.

```
rules/
├── port_scan.yml        # Unique ports per time window
├── syn_flood.yml        # SYN packet rate threshold
├── icmp_flood.yml       # ICMP echo rate threshold
├── brute_force.yml      # Login attempt rate + monitored ports
├── tcp_scans.yml        # Flag-based scans (NULL, XMAS, FIN …)
├── suspicious_ports.yml # Ports to flag on any connection
└── http_attacks.yml     # Regex patterns matched against HTTP payloads
```

**Example — lower the port scan threshold:**

```yaml
# rules/port_scan.yml
name: PORT SCAN
severity: HIGH
cooldown: 20
threshold:
  unique_ports: 10   # was 15
  time_window: 5     # was 10
```

**Example — add a new suspicious port:**

```yaml
# rules/suspicious_ports.yml  (append)
- port: 8888
  description: Common C2 / Jupyter
  severity: MEDIUM
```

**Example — add a new HTTP attack pattern:**

```yaml
# rules/http_attacks.yml  (append)
- name: Log4Shell
  pattern: '\$\{jndi:'
  severity: CRITICAL
```

---

## Configuration

Edit `config.py` to customize behavior:

```python
# AbuseIPDB threat intelligence (get free key at abuseipdb.com)
# Set via environment variable — never hardcode in config.py
# export ABUSEIPDB_KEY=your_key_here

# GeoIP — ip-api.com by default (no key needed)
# For offline use: download GeoLite2-City.mmdb from maxmind.com
GEOIP = {
    'enabled': True,
    'db_path': '',   # '/path/to/GeoLite2-City.mmdb'
}

# Trusted IPs and subnets (no alerts generated)
WHITELIST = {
    '127.0.0.1',
    '192.168.1.1',   # gateway
}
WHITELIST_NETWORKS = [
    # '172.18.0.0/16', # WSL virtual network — uncomment if running under WSL
    # '192.168.1.0/24', # Example: your local LAN
]
```

---

## Usage

```bash
# List available network interfaces
sudo python3 IDS.py --list-interfaces

# Standard mode (text alerts)
sudo python3 IDS.py -i eth0

# Live TUI dashboard
sudo python3 IDS.py -i eth0 --dashboard

# Custom baseline window and log file
sudo python3 IDS.py -i eth0 --baseline 60 --log /var/log/ids.log
```

### Environment variables

```bash
export ABUSEIPDB_KEY=your_key_here
sudo -E python3 IDS.py -i eth0 --dashboard
```

### Run as a systemd service (persistent)

```bash
# Edit ids.service: replace YOUR_USER and /path/to/IDS
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
  IDS ALERT REPORT  |  2026-05-27 01:09  →  2026-05-27 01:35
════════════════════════════════════════════════════════════════

  SEVERITY SUMMARY
  CRITICAL    ███░░░░░░░░░░░░░░░░░░░░░░░░░░░     3  (4.9%)
  HIGH        ████████████████████████░░░░░░    61  (83.6%)
  MEDIUM      █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     1  (1.4%)

  TOP ATTACKING IPs
  192.168.1.50    ██████████████████████████    61  [PORT SCAN, SYN FLOOD]
```

---

## PCAP Capture

HIGH and CRITICAL alerts automatically save the last 15 seconds of traffic from the source IP to `captures/`:

```
captures/
├── 20260527_010915_PORT_SCAN_x.x.x.x.pcap
└── 20260527_010916_SYN_FLOOD_x.x.x.x.pcap
```

Analyze captures:
```bash
tcpdump -r captures/file.pcap
# Or open in Wireshark
```

---

## Testing

```bash
# Port scan — triggers PORT SCAN (HIGH)
nmap -sS <target_ip>

# OS fingerprinting — triggers OS FINGERPRINTING (MEDIUM)
sudo nmap -O <target_ip>

# ICMP flood — triggers ICMP FLOOD (HIGH)
sudo ping -f -c 200 <target_ip>

# SYN flood — triggers SYN FLOOD (CRITICAL)
sudo hping3 -S --flood -p 80 <target_ip>

# ARP spoofing — triggers ARP SPOOFING (CRITICAL)
sudo python3 -c "
from scapy.all import sendp, ARP, Ether
pkt = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=2, psrc='192.168.1.1', hwsrc='aa:bb:cc:dd:ee:ff')
sendp(pkt, iface='eth0', count=3)
"
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
