import os

# Signature rules (thresholds, ports, HTTP patterns) are defined in rules/*.yml
# and loaded at startup via core.rule_loader.

ANOMALY_THRESHOLDS = {
    'baseline_window':    30,
    'pps_multiplier':     3.0,
    'new_ip_rate':        30,
    'port_diversity':     20,
    # Byte-rate exfiltration: alert when a single IP sustains more than N Mbps
    'byte_rate_mbps':     50,
    # C2 beaconing: minimum SYN samples needed before evaluating regularity
    'beacon_min_samples': 8,
    # C2 beaconing: coefficient of variation threshold (lower = more regular = suspicious)
    'beacon_cv_threshold': 0.15,
}

LOG_FILE = "ids_alerts.log"
INTERFACE = None

THREAT_INTEL = {
    'abuseipdb_key': os.getenv('ABUSEIPDB_KEY', ''),
    'min_score':     50,
    'cache_ttl':     3600,
    'feed_files':    [],
    'static_blacklist': [],
}

GEOIP = {
    'enabled': True,
    'db_path': '',   # Ruta a GeoLite2-City.mmdb para uso offline (opcional)
}

# IPs que nunca generarán alertas (tu gateway, DNS, hosts internos conocidos)
WHITELIST = {
    '127.0.0.1',
    '::1',
}

# Subredes confiables (añade tu red local, VPN, o la red virtual de WSL si aplica)
WHITELIST_NETWORKS: list[str] = [
    # '172.18.0.0/16',  # WSL virtual network — uncomment if running under WSL
    # '192.168.1.0/24', # Example: your local LAN
]
