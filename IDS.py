#!/usr/bin/env python3
"""
Network Intrusion Detection System
Signature + Anomaly based detection engine
Run as root/sudo on Linux or WSL.
"""

import sys
import os
import time
import argparse
import threading

from colorama import Fore, Style, init

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import LOG_FILE, INTERFACE, ANOMALY_THRESHOLDS, THREAT_INTEL, GEOIP
from core.alert import AlertManager
from core.dashboard import Dashboard
from core.geoip import GeoIPEngine
from core.pcap_writer import PcapCapture
from core.sniffer import PacketSniffer
from core.threat_intel import ThreatIntelEngine
from engines.signature import SignatureEngine
from engines.anomaly import AnomalyEngine

init(autoreset=True)

BANNER = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════╗
║   Network IDS  —  Signature + Anomaly Engine     ║
║   github.com/youruser/ids                        ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}"""


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows fallback
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0


def _list_interfaces():
    from scapy.all import get_if_list
    print(f"{Fore.CYAN}Available interfaces:{Style.RESET_ALL}")
    for iface in get_if_list():
        print(f"  {iface}")


def _parse_args():
    p = argparse.ArgumentParser(description="Network IDS — Signature + Anomaly Detection")
    p.add_argument('-i', '--interface', default=INTERFACE,
                   help='Network interface to monitor (default: auto)')
    p.add_argument('-l', '--log', default=LOG_FILE,
                   help=f'Alert log file (default: {LOG_FILE})')
    p.add_argument('-b', '--baseline', type=int, default=30,
                   help='Seconds to collect anomaly baseline (default: 30)')
    p.add_argument('--list-interfaces', action='store_true',
                   help='Print available interfaces and exit')
    p.add_argument('--dashboard', action='store_true',
                   help='Enable full-screen live dashboard (requires rich)')
    return p.parse_args()


def _stats_loop(alert_mgr, sniffer, anomaly_engine, start_time, stop_event):
    while not stop_event.wait(30):
        alert_mgr.print_stats(sniffer.packet_count, start_time)
        print(f"{Fore.CYAN}[Anomaly] {anomaly_engine.get_status()}{Style.RESET_ALL}\n")


def main():
    args = _parse_args()

    if args.list_interfaces:
        _list_interfaces()
        sys.exit(0)

    if not _is_root():
        print(f"{Fore.RED}[ERROR] Packet capture requires root/sudo privileges.{Style.RESET_ALL}")
        sys.exit(1)

    print(BANNER)

    # Override baseline window from CLI
    cfg = dict(ANOMALY_THRESHOLDS)
    cfg['baseline_window'] = args.baseline

    alert_mgr    = AlertManager(args.log)
    pcap_capture = PcapCapture(output_dir='captures', buffer_seconds=15)
    alert_mgr.set_pcap(pcap_capture)

    sig_engine  = SignatureEngine(alert_mgr)
    anom_engine = AnomalyEngine(alert_mgr, cfg)
    ti_engine   = ThreatIntelEngine(alert_mgr, THREAT_INTEL)
    sniffer     = PacketSniffer(args.interface, None)

    geoip_engine = None
    if GEOIP.get('enabled', True):
        geoip_engine = GeoIPEngine(db_path=GEOIP.get('db_path', ''))
        alert_mgr.set_geoip(geoip_engine)

    dashboard = None
    if args.dashboard:
        dashboard = Dashboard(sniffer, anom_engine, ti_engine, geoip_engine)
        alert_mgr.set_dashboard(dashboard)

    def on_packet(pkt):
        from scapy.layers.inet import IP
        pcap_capture.feed(pkt)
        sig_engine.analyze(pkt)
        anom_engine.analyze(pkt)
        if pkt.haslayer(IP):
            src = pkt[IP].src
            ti_engine.check(src)
            if geoip_engine:
                geoip_engine.prefetch(src)

    sniffer.callback = on_packet
    start_time = time.time()
    stop_event = threading.Event()

    if not dashboard:
        stats_thread = threading.Thread(
            target=_stats_loop,
            args=(alert_mgr, sniffer, anom_engine, start_time, stop_event),
            daemon=True,
        )
        iface = args.interface or 'auto-detect'
        print(f"{Fore.GREEN}[+] Interface  : {iface}")
        print(f"[+] Log file   : {args.log}")
        print(f"[+] Baseline   : {args.baseline}s")
        print(f"[+] Detections : Signatures + Anomalies + Threat Intel")
        print(f"\n{Fore.YELLOW}[*] Listening… Press Ctrl+C to stop.{Style.RESET_ALL}\n")

    try:
        sniffer.start()
        if dashboard:
            dashboard.start()
        else:
            stats_thread.start()
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        stop_event.set()
        sniffer.stop()
        if dashboard:
            dashboard.stop()
        print(f"\n{Fore.YELLOW}[*] Shutting down…{Style.RESET_ALL}")
        alert_mgr.print_stats(sniffer.packet_count, start_time)
        print(f"{Fore.GREEN}[+] Done. Alerts saved to: {args.log}{Style.RESET_ALL}")


if __name__ == '__main__':
    main()
