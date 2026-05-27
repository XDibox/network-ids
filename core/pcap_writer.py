import os
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.utils import PcapWriter


_CAPTURE_SEVERITIES = {'HIGH', 'CRITICAL'}


class PcapCapture:
    """
    Stores a rolling buffer of recent packets per source IP.
    When an alert fires, dumps the buffer to a .pcap file so the
    traffic that triggered the alert is preserved for forensic analysis.
    """

    def __init__(self, output_dir: str = 'captures', buffer_seconds: int = 15):
        self._dir            = output_dir
        self._buffer_seconds = buffer_seconds
        self._lock           = threading.Lock()
        # ip -> deque of (timestamp, packet)
        self._buffers: dict  = defaultdict(deque)

        os.makedirs(output_dir, exist_ok=True)

    # ── Public ────────────────────────────────────────────────────────────────

    def feed(self, packet):
        """Buffer every packet indexed by source IP."""
        from scapy.layers.inet import IP
        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        now = time.time()

        with self._lock:
            buf = self._buffers[src]
            buf.append((now, packet))
            # Evict packets older than the buffer window
            while buf and now - buf[0][0] > self._buffer_seconds:
                buf.popleft()

    def save(self, severity: str, category: str, src_ip: str):
        """Dump the buffer for src_ip to a .pcap file if severity warrants it."""
        if severity not in _CAPTURE_SEVERITIES:
            return

        with self._lock:
            packets = list(self._buffers.get(src_ip, []))

        if not packets:
            return

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_cat  = category.replace(' ', '_').replace('/', '-')
        filename  = f"{timestamp}_{safe_cat}_{src_ip}.pcap"
        filepath  = os.path.join(self._dir, filename)

        try:
            with PcapWriter(filepath, sync=True) as writer:
                for _, pkt in packets:
                    writer.write(pkt)
            return filepath
        except Exception as e:
            print(f"[PCAP] Failed to write {filepath}: {e}")
            return None
