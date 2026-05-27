import re
import time
from collections import defaultdict, deque

from config import SIGNATURE_THRESHOLDS, SUSPICIOUS_PORTS, HTTP_PATTERNS
from core.whitelist import is_whitelisted


class SignatureEngine:
    """Rule-based detection against known attack patterns."""

    def __init__(self, alert_manager):
        self._alert = alert_manager
        self._port_tracker  = defaultdict(deque)
        self._icmp_tracker  = defaultdict(deque)
        self._syn_tracker   = defaultdict(deque)
        self._brute_tracker = defaultdict(lambda: defaultdict(deque))
        self._arp_table:    dict = {}              # ip -> mac (ARP spoofing)
        self._dns_tracker   = defaultdict(deque)  # src -> [(ts, size)]
        self._fp_tracker    = defaultdict(deque)  # src -> [ts]  (OS fingerprint probes)
        self._cooldown: dict = defaultdict(float)

    def _cooldown_ok(self, key: str, now: float, seconds: float) -> bool:
        if now - self._cooldown[key] >= seconds:
            self._cooldown[key] = now
            return True
        return False

    # ── Public ──────────────────────────────────────────────────────────────

    def analyze(self, packet):
        from scapy.layers.inet import IP, TCP, ICMP

        # ARP spoofing does not have an IP layer — check separately
        if packet.haslayer('ARP'):
            self._check_arp_spoofing(packet)
            return

        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst

        if is_whitelisted(src):
            return

        if packet.haslayer(TCP):
            self._check_port_scan(packet, src)
            self._check_tcp_flags(packet, src)
            self._check_syn_flood(packet, src, dst)
            self._check_brute_force(packet, src)
            self._check_suspicious_ports(packet, src, dst, 'TCP')
            self._check_http_payload(packet, src)
            self._check_os_fingerprint(packet, src)

        if packet.haslayer(ICMP):
            self._check_icmp_flood(packet, src, dst)
            self._check_os_fingerprint(packet, src)

        if packet.haslayer('UDP'):
            self._check_suspicious_ports(packet, src, dst, 'UDP')
            if packet.haslayer('DNS'):
                self._check_dns_amplification(packet, src)

    # ── Private helpers ──────────────────────────────────────────────────────

    def _check_port_scan(self, packet, src):
        cfg    = SIGNATURE_THRESHOLDS['port_scan']
        now    = time.time()
        window = cfg['time_window']
        dport  = packet['TCP'].dport

        track = self._port_tracker[src]
        track.append((now, dport))
        while track and now - track[0][0] > window:
            track.popleft()

        unique = len({p for _, p in track})
        if unique >= cfg['unique_ports'] and self._cooldown_ok(f'portscan_{src}', now, 20):
            self._alert.alert(
                'HIGH', 'PORT SCAN', src,
                f"{unique} unique ports in {window}s", f"last={dport}",
            )
            self._port_tracker[src].clear()

    def _check_tcp_flags(self, packet, src):
        flags = packet['TCP'].flags

        if flags == 0x00:
            self._alert.alert('MEDIUM', 'NULL SCAN', src, "TCP packet with no flags")
        elif int(flags) == 0x29:
            self._alert.alert('MEDIUM', 'XMAS SCAN', src, "FIN+PSH+URG flags set")
        elif int(flags) == 0x01:
            self._alert.alert('LOW',    'FIN SCAN',  src, "Only FIN flag set")

    def _check_syn_flood(self, packet, src, dst):
        if int(packet['TCP'].flags) != 0x02:
            return

        cfg    = SIGNATURE_THRESHOLDS['syn_flood']
        now    = time.time()
        window = cfg['time_window']

        track = self._syn_tracker[src]
        track.append(now)
        while track and now - track[0] > window:
            track.popleft()

        if len(track) >= cfg['packet_count'] and self._cooldown_ok(f'synflood_{src}', now, 15):
            self._alert.alert(
                'CRITICAL', 'SYN FLOOD', src,
                f"{len(track)} SYN pkts in {window}s", f"dst={dst}",
            )
            self._syn_tracker[src].clear()

    def _check_brute_force(self, packet, src):
        cfg   = SIGNATURE_THRESHOLDS['brute_force']
        dport = packet['TCP'].dport

        if dport not in cfg['ports']:
            return
        if not (int(packet['TCP'].flags) & 0x02):
            return

        now    = time.time()
        window = cfg['time_window']

        track = self._brute_tracker[src][dport]
        track.append(now)
        while track and now - track[0] > window:
            track.popleft()

        if len(track) >= cfg['connection_count']:
            svc = {22: 'SSH', 21: 'FTP', 3389: 'RDP', 23: 'Telnet'}.get(dport, str(dport))
            self._alert.alert(
                'HIGH', 'BRUTE FORCE', src,
                f"{svc} — {len(track)} attempts in {window}s",
            )
            self._brute_tracker[src][dport].clear()

    def _check_suspicious_ports(self, packet, src, dst, proto):
        dport = packet[proto].dport if packet.haslayer(proto) else None
        if dport and dport in SUSPICIOUS_PORTS:
            self._alert.alert(
                'HIGH', 'SUSPICIOUS PORT', src,
                f"Port {dport} ({SUSPICIOUS_PORTS[dport]})", f"dst={dst}",
            )

    def _check_http_payload(self, packet, src):
        if not packet.haslayer('Raw'):
            return
        try:
            payload = packet['Raw'].load.decode('utf-8', errors='ignore')
        except Exception:
            return

        if not any(kw in payload for kw in ('HTTP', 'GET ', 'POST ', 'PUT ')):
            return

        for pattern, attack_type in HTTP_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                self._alert.alert(
                    'HIGH', attack_type, src,
                    "Malicious pattern in HTTP payload", f"rule={pattern[:30]}",
                )
                break

    def _check_icmp_flood(self, packet, src, dst):
        from scapy.layers.inet import ICMP
        if packet[ICMP].type != 8:
            return

        cfg    = SIGNATURE_THRESHOLDS['icmp_flood']
        now    = time.time()
        window = cfg['time_window']

        track = self._icmp_tracker[src]
        track.append(now)
        while track and now - track[0] > window:
            track.popleft()

        if len(track) >= cfg['packet_count'] and self._cooldown_ok(f'icmpflood_{src}', now, 15):
            self._alert.alert(
                'HIGH', 'ICMP FLOOD', src,
                f"{len(track)} echo requests in {window}s", f"dst={dst}",
            )
            self._icmp_tracker[src].clear()

    # ── ARP Spoofing ─────────────────────────────────────────────────────────

    def _check_arp_spoofing(self, packet):
        arp = packet['ARP']

        if arp.op != 2:  # Solo ARP replies (is-at)
            return

        src_ip  = arp.psrc
        src_mac = arp.hwsrc.lower()

        if not src_ip or src_ip == '0.0.0.0':
            return

        if is_whitelisted(src_ip):
            return

        known_mac = self._arp_table.get(src_ip)
        if known_mac is None:
            self._arp_table[src_ip] = src_mac
        elif known_mac != src_mac:
            self._alert.alert(
                'CRITICAL', 'ARP SPOOFING', src_ip,
                f"MAC changed {known_mac} → {src_mac}",
            )
            self._arp_table[src_ip] = src_mac  # Actualiza para no repetir la misma alerta

    # ── DNS Amplification ────────────────────────────────────────────────────

    def _check_dns_amplification(self, packet, src):
        dns = packet['DNS']
        now = time.time()

        # Solo respuestas DNS (qr=1) de gran tamaño
        if dns.qr != 1:
            return

        pkt_size = len(packet)
        if pkt_size < 512:
            return

        track = self._dns_tracker[src]
        track.append((now, pkt_size))
        while track and now - track[0][0] > 10:
            track.popleft()

        # Alerta si hay múltiples respuestas grandes o una respuesta enorme
        total_bytes = sum(s for _, s in track)
        if pkt_size > 3000 and self._cooldown_ok(f'dnsamp_{src}', now, 30):
            self._alert.alert(
                'HIGH', 'DNS AMPLIFICATION', src,
                f"Oversized DNS response: {pkt_size} bytes",
            )
        elif len(track) >= 20 and self._cooldown_ok(f'dnsflood_{src}', now, 30):
            self._alert.alert(
                'MEDIUM', 'DNS FLOOD', src,
                f"{len(track)} DNS responses in 10s ({total_bytes} bytes total)",
            )

        # ANY query (vector de amplificación clásico)
        if dns.qr == 0 and dns.qdcount > 0:
            try:
                if dns.qd.qtype == 255:  # ANY
                    self._alert.alert(
                        'MEDIUM', 'DNS ANY QUERY', src,
                        f"DNS ANY query — common amplification vector",
                        f"qname={dns.qd.qname.decode(errors='ignore')}",
                    )
            except Exception:
                pass

    # ── OS Fingerprinting ────────────────────────────────────────────────────

    def _check_os_fingerprint(self, packet, src):
        """Detect Nmap OS detection probes and TTL-based fingerprinting."""
        now = time.time()
        reason = None

        if packet.haslayer('TCP'):
            tcp   = packet['TCP']
            flags = int(tcp.flags)
            opts  = {k: v for k, v in tcp.options} if tcp.options else {}

            # Nmap OS probe T2-T7: SYN con window=128 o 256 y opciones específicas
            if flags == 0x02 and tcp.window in (1, 2, 4, 8, 16, 32, 64, 128):
                if 'WScale' in opts and 'Timestamp' in opts:
                    reason = f"Nmap-style SYN probe (win={tcp.window}, opts={list(opts.keys())})"

            # ECN probe: SYN + ECE + CWR
            elif flags == 0xC2:
                reason = "ECN probe (SYN+ECE+CWR) — Nmap OS detection"

            # URG sin datos (probe U1)
            elif (flags & 0x20) and not packet.haslayer('Raw'):
                reason = "URG probe without payload — OS fingerprinting"

        if packet.haslayer('ICMP'):
            icmp = packet['ICMP']
            ip   = packet['IP']
            # TTL muy bajo = traceroute o fingerprint probe
            if ip.ttl <= 3 and icmp.type == 8:
                reason = f"ICMP echo with TTL={ip.ttl} — TTL fingerprinting"
            # IE probes de Nmap: ICMP con código y datos específicos
            elif icmp.type == 8 and icmp.code != 0:
                reason = f"ICMP echo with non-zero code={icmp.code} — OS probe"

        if reason:
            track = self._fp_tracker[src]
            track.append(now)
            while track and now - track[0] > 60:
                track.popleft()

            if len(track) >= 3 and self._cooldown_ok(f'osfp_{src}', now, 60):
                self._alert.alert(
                    'MEDIUM', 'OS FINGERPRINTING', src,
                    f"{len(track)} probes in 60s — {reason}",
                )
