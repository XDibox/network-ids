import logging
import datetime
import subprocess
import shutil
from colorama import Fore, Style, init

init(autoreset=True)

_NOTIFY_SEVERITIES = {'HIGH', 'CRITICAL'}

_TOAST_ICONS = {
    'HIGH':     'Warning',
    'CRITICAL': 'Error',
}


def _send_windows_toast(title: str, message: str, icon: str = 'Warning'):
    """Send a Windows toast notification from WSL via PowerShell."""
    if not shutil.which('powershell.exe'):
        return
    ps = (
        "[void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');"
        "$n = New-Object System.Windows.Forms.NotifyIcon;"
        "$n.Icon = [System.Drawing.SystemIcons]::%(icon)s;"
        "$n.Visible = $true;"
        "$n.ShowBalloonTip(6000, '%(title)s', '%(msg)s', [System.Windows.Forms.ToolTipIcon]::%(icon)s);"
        "Start-Sleep -Milliseconds 6500;"
        "$n.Dispose()"
    ) % {'icon': icon, 'title': title, 'msg': message}
    subprocess.Popen(
        ['powershell.exe', '-WindowStyle', 'Hidden', '-Command', ps],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

_SEVERITY_COLORS = {
    'LOW':      Fore.YELLOW,
    'MEDIUM':   Fore.LIGHTYELLOW_EX,
    'HIGH':     Fore.RED,
    'CRITICAL': Fore.MAGENTA,
}

_SEVERITY_ICONS = {
    'LOW':      '[!]     ',
    'MEDIUM':   '[!!]    ',
    'HIGH':     '[!!!]   ',
    'CRITICAL': '[CRIT]  ',
}

_LOG_LEVELS = {
    'LOW':      logging.WARNING,
    'MEDIUM':   logging.WARNING,
    'HIGH':     logging.ERROR,
    'CRITICAL': logging.CRITICAL,
}


class AlertManager:
    def __init__(self, log_file: str):
        self._log_file  = log_file
        self._counts    = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        self._pcap      = None
        self._dashboard = None
        self._geoip     = None
        self._setup_logger()

    def set_pcap(self, pcap_capture):
        self._pcap = pcap_capture

    def set_dashboard(self, dashboard):
        self._dashboard = dashboard

    def set_geoip(self, geoip):
        self._geoip = geoip

    def _setup_logger(self):
        logging.basicConfig(
            filename=self._log_file,
            format='%(asctime)s | %(levelname)s | %(message)s',
            level=logging.INFO,
        )
        self._logger = logging.getLogger('IDS')

    def alert(self, severity: str, category: str, src: str, description: str, extra: str = ''):
        timestamp = datetime.datetime.now().strftime('%H:%M:%S')
        color = _SEVERITY_COLORS.get(severity, Fore.WHITE)
        icon  = _SEVERITY_ICONS.get(severity, '[?]')

        geo = self._geoip.format(src) if self._geoip else ''
        extra_parts = [e for e in (extra, geo) if e]
        extra_part  = f'  ({" | ".join(extra_parts)})' if extra_parts else ''
        line = f"{icon} {category:<20} {src:<18} {description}{extra_part}"

        # En modo dashboard el Live de rich gestiona el terminal — no imprimir
        if not self._dashboard:
            print(f"{color}[{timestamp}] {line}{Style.RESET_ALL}")

        self._logger.log(
            _LOG_LEVELS.get(severity, logging.INFO),
            f"{severity} | {category} | {src} | {description}{extra_part}",
        )
        self._counts[severity] = self._counts.get(severity, 0) + 1

        if self._dashboard:
            self._dashboard.record(severity, category, src, description)

        if severity in _NOTIFY_SEVERITIES:
            _send_windows_toast(
                title=f"IDS — {severity}: {category}",
                message=f"{src}  {description}",
                icon=_TOAST_ICONS.get(severity, 'Warning'),
            )
            if self._pcap:
                filepath = self._pcap.save(severity, category, src)
                if filepath:
                    print(f"{Fore.CYAN}  [PCAP] Saved → {filepath}{Style.RESET_ALL}")

    def print_stats(self, packet_count: int, start_time: float):
        import time
        elapsed = time.time() - start_time
        pps = packet_count / elapsed if elapsed > 0 else 0
        c = self._counts

        print(f"\n{Fore.CYAN}{'─'*64}")
        print(f"  IDS STATS  |  runtime {elapsed:.0f}s  |  {packet_count} pkts  |  {pps:.1f} pps")
        print(f"  Alerts → LOW:{c['LOW']}  MEDIUM:{c['MEDIUM']}  HIGH:{c['HIGH']}  CRITICAL:{c['CRITICAL']}")
        print(f"{'─'*64}{Style.RESET_ALL}\n")
