SIGNATURE_THRESHOLDS = {
    'port_scan': {
        'unique_ports': 15,
        'time_window': 10,
    },
    'icmp_flood': {
        'packet_count': 100,
        'time_window': 5,
    },
    'syn_flood': {
        'packet_count': 200,
        'time_window': 5,
    },
    'brute_force': {
        'connection_count': 10,
        'time_window': 30,
        'ports': [22, 21, 3389, 23],
    },
}

ANOMALY_THRESHOLDS = {
    'baseline_window': 30,
    'pps_multiplier': 3.0,
    'new_ip_rate': 30,
    'port_diversity': 20,
}

SUSPICIOUS_PORTS = {
    4444: 'Metasploit default',
    1337: 'Common backdoor',
    31337: 'Back Orifice',
    12345: 'NetBus',
    5555: 'Android Debug Bridge',
    9001: 'Tor relay',
    6666: 'IRC/Malware',
    6667: 'IRC/Malware',
}

HTTP_PATTERNS = [
    (r"union.*select", "SQL Injection"),
    (r"'.*or.*'.*=.*'", "SQL Injection"),
    (r"\.\./\.\.", "Directory Traversal"),
    (r"<script", "XSS Attempt"),
    (r"/etc/passwd", "LFI Attempt"),
    (r"cmd\.exe|/bin/sh|/bin/bash", "Command Injection"),
    (r"eval\(|base64_decode\(", "Code Injection"),
]

LOG_FILE = "ids_alerts.log"
INTERFACE = None

# IPs que nunca generarán alertas (tu gateway, DNS, hosts internos conocidos)
WHITELIST = {
    '127.0.0.1',
    '::1',
}

# Subredes confiables en notación CIDR (ej: '192.168.1.0/24')
WHITELIST_NETWORKS = []
