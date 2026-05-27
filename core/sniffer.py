import threading
from scapy.all import sniff


class PacketSniffer:
    def __init__(self, interface, callback):
        self.interface = interface
        self.callback = callback
        self.packet_count = 0
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._sniff, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _sniff(self):
        kwargs = {'prn': self._process, 'store': False}
        if self.interface:
            kwargs['iface'] = self.interface
        sniff(**kwargs)

    def _process(self, packet):
        if self._running:
            self.packet_count += 1
            self.callback(packet)
