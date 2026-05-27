import threading
import time
from collections import defaultdict, deque
from datetime import timedelta

from rich import box
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


_SEV_COLOR = {
    'CRITICAL': 'magenta',
    'HIGH':     'red',
    'MEDIUM':   'yellow',
    'LOW':      'green',
}


class Dashboard:
    """Full-screen live TUI dashboard. Activated with --dashboard flag."""

    MAX_RECENT = 18

    def __init__(self, sniffer, anomaly_engine, ti_engine=None, geoip_engine=None):
        self._sniffer = sniffer
        self._anomaly = anomaly_engine
        self._ti      = ti_engine
        self._geoip   = geoip_engine
        self._start   = time.time()

        self._alert_counts = defaultdict(int)
        self._recent:  deque = deque(maxlen=self.MAX_RECENT)
        self._top_ips: dict  = defaultdict(lambda: {'count': 0, 'cats': set()})
        self._lock = threading.Lock()

        self._live: Live | None = None

    # ── Public ────────────────────────────────────────────────────────────────

    def record(self, severity: str, category: str, src: str, description: str):
        with self._lock:
            self._alert_counts[severity] += 1
            self._recent.append({
                'time': time.strftime('%H:%M:%S'),
                'sev':  severity,
                'cat':  category,
                'src':  src,
                'desc': description,
            })
            self._top_ips[src]['count'] += 1
            self._top_ips[src]['cats'].add(category)

    def start(self):
        self._live = Live(
            self._render(),
            refresh_per_second=1,
            screen=True,
        )
        self._live.start()
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        if self._live:
            self._live.stop()

    # ── Render ────────────────────────────────────────────────────────────────

    def _loop(self):
        while True:
            time.sleep(1)
            if self._live:
                self._live.update(self._render())

    def _render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name='header',   size=3),
            Layout(name='row1',     size=8),
            Layout(name='top_ips',  size=9),
            Layout(name='alerts'),
        )
        layout['row1'].split_row(
            Layout(name='packets', ratio=1),
            Layout(name='counts',  ratio=1),
            Layout(name='engines', ratio=1),
        )

        layout['header'].update(self._header())
        layout['row1']['packets'].update(self._packets())
        layout['row1']['counts'].update(self._counts())
        layout['row1']['engines'].update(self._engines())
        layout['top_ips'].update(self._top_ips_panel())
        layout['alerts'].update(self._alerts_panel())

        return layout

    def _header(self) -> Panel:
        elapsed = timedelta(seconds=int(time.time() - self._start))
        iface   = self._sniffer.interface or 'auto-detect'
        return Panel(
            f"[bold cyan]Network IDS  —  Signature + Anomaly + Threat Intel[/]"
            f"   |   Runtime: [white]{elapsed}[/]   |   Interface: [white]{iface}[/]",
            style='cyan',
        )

    def _packets(self) -> Panel:
        elapsed = time.time() - self._start
        pps     = self._sniffer.packet_count / elapsed if elapsed > 0 else 0

        t = Table(box=None, show_header=False, padding=(0, 2))
        t.add_row('[cyan]Total packets[/]', f'[bold white]{self._sniffer.packet_count:,}[/]')
        t.add_row('[cyan]Current rate[/]',  f'[bold white]{pps:.1f} pps[/]')
        return Panel(t, title='[bold]TRAFFIC[/]', border_style='blue')

    def _counts(self) -> Panel:
        t = Table(box=None, show_header=False, padding=(0, 2))
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            count = self._alert_counts.get(sev, 0)
            color = _SEV_COLOR[sev]
            t.add_row(f'[{color}]{sev}[/]', f'[bold white]{count}[/]')
        total = sum(self._alert_counts.values())
        t.add_row('[white]─────────[/]', '[white]───[/]')
        t.add_row('[bold white]TOTAL[/]', f'[bold white]{total}[/]')
        return Panel(t, title='[bold]ALERTS[/]', border_style='red')

    def _engines(self) -> Panel:
        anom = self._anomaly.get_status()
        anom_color = 'yellow' if 'Building' in anom else 'green'
        anom_label = anom if 'Building' in anom else 'active'

        ti_label = 'API + local' if (self._ti and self._ti._api_key) else 'local only'

        t = Table(box=None, show_header=False, padding=(0, 2))
        t.add_row('[cyan]Signature[/]',   '[green]active[/]')
        t.add_row('[cyan]Anomaly[/]',     f'[{anom_color}]{anom_label}[/]')
        t.add_row('[cyan]Threat Intel[/]', f'[green]{ti_label}[/]')
        t.add_row('[cyan]PCAP capture[/]', '[green]active[/]')
        return Panel(t, title='[bold]ENGINES[/]', border_style='blue')

    def _top_ips_panel(self) -> Panel:
        t = Table(box=box.SIMPLE, show_header=True, header_style='bold cyan', padding=(0, 1))
        t.add_column('Source IP',    style='white',      width=20)
        t.add_column('Alerts',       style='bold white', width=8)
        t.add_column('Location',     style='cyan',       width=28)
        t.add_column('Attack Types', style='yellow')

        with self._lock:
            top = sorted(
                self._top_ips.items(),
                key=lambda x: x[1]['count'],
                reverse=True,
            )[:5]

        for ip, data in top:
            cats = ', '.join(sorted(data['cats']))
            geo  = self._geoip.format(ip) if self._geoip else ''
            t.add_row(ip, str(data['count']), geo, cats)

        return Panel(t, title='[bold]TOP ATTACKING IPs[/]', border_style='red')

    def _alerts_panel(self) -> Panel:
        t = Table(box=box.SIMPLE, show_header=True, header_style='bold cyan', padding=(0, 1))
        t.add_column('Time',       width=10)
        t.add_column('Severity',   width=10)
        t.add_column('Category',   width=22)
        t.add_column('Source IP',  width=18)
        t.add_column('Description')

        with self._lock:
            alerts = list(self._recent)

        for a in reversed(alerts):
            color = _SEV_COLOR.get(a['sev'], 'white')
            t.add_row(
                a['time'],
                f"[{color}]{a['sev']}[/]",
                a['cat'],
                a['src'],
                a['desc'],
            )

        return Panel(t, title='[bold]RECENT ALERTS[/]', border_style='yellow')
