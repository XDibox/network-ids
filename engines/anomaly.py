import time
import statistics
from collections import defaultdict, deque
from core.whitelist import is_whitelisted


class AnomalyEngine:
    """Statistical baseline + deviation-based anomaly detection."""

    def __init__(self, alert_manager, config: dict):
        self._alert  = alert_manager
        self._config = config

        # Baseline state
        self._start_time      = time.time()
        self._baseline_built  = False
        self._avg_pps         = 0.0
        self._std_pps         = 0.0
        self._baseline_ratios = {}

        # Per-second counter for baseline collection
        self._cur_sec   = int(time.time())
        self._cur_count = 0
        self._pps_samples: deque = deque()

        # Per-IP tracking
        self._ip_rate  = defaultdict(deque)   # src -> [timestamps]
        self._ip_bytes = defaultdict(deque)   # src -> [(ts, bytes)]
        self._ip_ports = defaultdict(deque)   # src -> [(ts, port)]
        self._known_ips: set = set()
        self._new_ips: deque = deque()        # [(ts, ip)]

        # Beaconing: src -> {(dst, dport) -> [timestamps of SYN packets]}
        self._beacon_tracker: dict = defaultdict(lambda: defaultdict(deque))

        # Protocol distribution
        self._proto_counts: dict = defaultdict(int)
        self._total_pkts   = 0

        # Alert cooldown: key -> last_alert_ts
        self._cooldown: dict = defaultdict(float)

    # ── Public ───────────────────────────────────────────────────────────────

    def analyze(self, packet):
        from scapy.layers.inet import IP

        if not packet.haslayer(IP):
            return

        now   = time.time()
        src   = packet[IP].src
        proto = packet[IP].proto

        if is_whitelisted(src):
            return

        self._total_pkts += 1
        self._proto_counts[proto] += 1

        if not self._baseline_built:
            self._collect(src, now)
            if now - self._start_time >= self._config.get('baseline_window', 30):
                self._build_baseline()
            return

        self._check_packet_rate(src, now)
        self._check_byte_rate(src, now, len(packet))
        self._check_new_ip(src, now)
        self._check_port_diversity(src, now, packet)
        self._check_protocol_anomaly(proto, now)
        self._check_beaconing(src, now, packet)

    def is_ready(self) -> bool:
        return self._baseline_built

    def get_status(self) -> str:
        if not self._baseline_built:
            elapsed   = time.time() - self._start_time
            remaining = self._config.get('baseline_window', 30) - elapsed
            return f"Building baseline — {max(0, remaining):.0f}s remaining"
        return (f"Active | baseline {self._avg_pps:.1f} pps "
                f"(±{self._std_pps:.1f}) | known IPs {len(self._known_ips)}")

    # ── Baseline collection ───────────────────────────────────────────────────

    def _collect(self, src: str, now: float):
        self._known_ips.add(src)
        sec = int(now)
        if sec != self._cur_sec:
            if self._cur_count:
                self._pps_samples.append(self._cur_count)
            self._cur_sec   = sec
            self._cur_count = 0
        self._cur_count += 1

    def _build_baseline(self):
        samples = list(self._pps_samples)
        if len(samples) >= 2:
            self._avg_pps = statistics.mean(samples)
            self._std_pps = statistics.stdev(samples)
        else:
            self._avg_pps = max(samples[0] if samples else 1, 1)
            self._std_pps = self._avg_pps * 0.1

        if self._total_pkts:
            self._baseline_ratios = {
                p: c / self._total_pkts for p, c in self._proto_counts.items()
            }

        self._baseline_built = True
        from colorama import Fore, Style
        print(
            f"\n{Fore.GREEN}[*] Anomaly baseline ready: "
            f"{self._avg_pps:.1f} pps (±{self._std_pps:.1f}), "
            f"known IPs: {len(self._known_ips)}{Style.RESET_ALL}\n"
        )

    # ── Active detection ──────────────────────────────────────────────────────

    def _check_packet_rate(self, src: str, now: float):
        window  = 10
        tracker = self._ip_rate[src]
        tracker.append(now)
        while tracker and now - tracker[0] > window:
            tracker.popleft()

        rate      = len(tracker) / window
        threshold = self._avg_pps * self._config.get('pps_multiplier', 3.0)

        if rate > threshold and self._cooldown_ok(f'rate_{src}', now, 30):
            self._alert.alert(
                'HIGH', 'TRAFFIC ANOMALY', src,
                f"rate {rate:.1f} pps > threshold {threshold:.1f} pps",
            )

    def _check_new_ip(self, src: str, now: float):
        if src in self._known_ips:
            return

        self._known_ips.add(src)
        self._new_ips.append((now, src))
        while self._new_ips and now - self._new_ips[0][0] > 60:
            self._new_ips.popleft()

        threshold = self._config.get('new_ip_rate', 30)
        if len(self._new_ips) >= threshold and self._cooldown_ok('ip_sweep', now, 60):
            self._alert.alert(
                'MEDIUM', 'IP SWEEP', src,
                f"{len(self._new_ips)} new IPs in 60s (threshold {threshold})",
            )

    def _check_port_diversity(self, src: str, now: float, packet):
        proto = None
        if packet.haslayer('TCP'):
            proto = 'TCP'
        elif packet.haslayer('UDP'):
            proto = 'UDP'
        if not proto:
            return

        dport   = packet[proto].dport
        tracker = self._ip_ports[src]
        tracker.append((now, dport))
        while tracker and now - tracker[0][0] > 60:
            tracker.popleft()

        unique    = len({p for _, p in tracker})
        threshold = self._config.get('port_diversity', 20)

        if unique >= threshold and self._cooldown_ok(f'div_{src}', now, 60):
            self._alert.alert(
                'MEDIUM', 'PORT DIVERSITY', src,
                f"{unique} unique ports in 60s (threshold {threshold})",
            )

    def _check_protocol_anomaly(self, proto: int, now: float):
        if self._total_pkts < 500:
            return

        baseline = self._baseline_ratios.get(proto, 0)
        if baseline < 0.05:
            return

        current = self._proto_counts[proto] / self._total_pkts
        if current > baseline * 3 and self._cooldown_ok(f'proto_{proto}', now, 120):
            name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(proto, str(proto))
            self._alert.alert(
                'MEDIUM', 'PROTOCOL ANOMALY', 'network',
                f"{name} ratio {current:.1%} vs baseline {baseline:.1%}",
            )

    def _check_byte_rate(self, src: str, now: float, pkt_len: int):
        window  = 10
        tracker = self._ip_bytes[src]
        tracker.append((now, pkt_len))
        while tracker and now - tracker[0][0] > window:
            tracker.popleft()

        total_bytes = sum(b for _, b in tracker)
        rate_mbps   = (total_bytes * 8) / (window * 1_000_000)
        threshold   = self._config.get('byte_rate_mbps', 50)

        if rate_mbps > threshold and self._cooldown_ok(f'byterate_{src}', now, 60):
            self._alert.alert(
                'HIGH', 'DATA EXFILTRATION', src,
                f"Sustained high byte rate: {rate_mbps:.1f} Mbps (threshold {threshold} Mbps)",
            )

    def _check_beaconing(self, src: str, now: float, packet):
        if not packet.haslayer('TCP'):
            return
        if int(packet['TCP'].flags) != 0x02:  # SYN only
            return

        try:
            from scapy.layers.inet import IP
            dst   = packet[IP].dst
            dport = packet['TCP'].dport
        except Exception:
            return

        tracker = self._beacon_tracker[src][(dst, dport)]
        tracker.append(now)
        while tracker and now - tracker[0] > 1800:
            tracker.popleft()

        min_samples = self._config.get('beacon_min_samples', 8)
        if len(tracker) < min_samples:
            return

        times     = list(tracker)
        intervals = [times[i + 1] - times[i] for i in range(len(times) - 1)]

        mean_iv = statistics.mean(intervals)
        if mean_iv < 5 or mean_iv > 300:
            return

        try:
            stdev_iv = statistics.stdev(intervals)
        except statistics.StatisticsError:
            return

        cv = stdev_iv / mean_iv if mean_iv > 0 else 1.0
        cv_threshold = self._config.get('beacon_cv_threshold', 0.15)

        if cv < cv_threshold and self._cooldown_ok(f'beacon_{src}_{dst}_{dport}', now, 300):
            self._alert.alert(
                'HIGH', 'C2 BEACONING', src,
                f"Regular connections to {dst}:{dport} every ~{mean_iv:.0f}s (CV={cv:.3f})",
            )

    def _cooldown_ok(self, key: str, now: float, seconds: float) -> bool:
        if now - self._cooldown[key] >= seconds:
            self._cooldown[key] = now
            return True
        return False
