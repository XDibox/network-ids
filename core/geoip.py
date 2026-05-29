import json
import queue
import threading
import time
import urllib.parse
import urllib.request

_PRIVATE_PREFIXES = (
    '10.', '127.', '169.254.', '::1',
    '172.16.', '172.17.', '172.18.', '172.19.', '172.20.',
    '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
    '172.26.', '172.27.', '172.28.', '172.29.', '172.30.',
    '172.31.', '192.168.',
)

_MAX_SEEN  = 50_000
_MAX_CACHE = 10_000

_API_FIELDS = 'country,countryCode,regionName,city,isp,as,proxy,hosting'


class GeoIPEngine:
    """
    Resolves geographic location for IP addresses.
    - If a MaxMind GeoLite2-City.mmdb path is configured: offline, instant, no rate limit.
    - Otherwise: ip-api.com (free, no key, ~45 req/min).
    Results are cached permanently for the process lifetime.
    """

    def __init__(self, db_path: str = ''):
        self._db      = self._load_maxmind(db_path)
        self._cache:  dict  = {}
        self._seen:   set   = set()
        self._queue:  queue.Queue = queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()

        src = f'MaxMind DB ({db_path})' if self._db else 'ip-api.com'
        print(f"[GeoIP] Source: {src}")

    # ── Public ────────────────────────────────────────────────────────────────

    def prefetch(self, ip: str):
        """Queue an IP for background resolution (call on every new IP seen)."""
        if len(self._seen) >= _MAX_SEEN:
            self._seen.clear()
        if ip not in self._seen and not _is_private(ip):
            self._seen.add(ip)
            self._queue.put(ip)

    def lookup(self, ip: str) -> dict | None:
        """Return cached GeoIP data instantly, or None if not yet resolved."""
        return self._cache.get(ip)

    def format(self, ip: str) -> str:
        """Return a compact location string for alert display."""
        d = self._cache.get(ip)
        if not d:
            return ''
        parts = []
        if d.get('countryCode'):
            parts.append(d['countryCode'])
        if d.get('city'):
            parts.append(d['city'])
        if d.get('isp'):
            parts.append(d['isp'])
        if d.get('proxy'):
            parts.append('VPN/Proxy')
        if d.get('hosting'):
            parts.append('Hosting/DC')
        return ' | '.join(parts)

    # ── Private ───────────────────────────────────────────────────────────────

    def _worker(self):
        while True:
            ip = self._queue.get()
            if ip not in self._cache:
                if self._db:
                    self._lookup_maxmind(ip)
                else:
                    self._lookup_api(ip)
                    time.sleep(1.4)  # Stay under 45 req/min

    def _lookup_api(self, ip: str):
        try:
            url = (
                f"https://ip-api.com/json/{urllib.parse.quote(ip)}"
                f"?fields={_API_FIELDS}"
            )
            with urllib.request.urlopen(url, timeout=6) as resp:
                data = json.loads(resp.read().decode())
            if data.get('status') == 'success':
                if len(self._cache) >= _MAX_CACHE:
                    for k in list(self._cache.keys())[:_MAX_CACHE // 4]:
                        del self._cache[k]
                self._cache[ip] = {
                    'country':     data.get('country', ''),
                    'countryCode': data.get('countryCode', ''),
                    'region':      data.get('regionName', ''),
                    'city':        data.get('city', ''),
                    'isp':         data.get('isp', ''),
                    'asn':         data.get('as', ''),
                    'proxy':       data.get('proxy', False),
                    'hosting':     data.get('hosting', False),
                }
        except Exception:
            pass

    def _lookup_maxmind(self, ip: str):
        try:
            resp = self._db.city(ip)
            self._cache[ip] = {
                'country':     resp.country.name or '',
                'countryCode': resp.country.iso_code or '',
                'region':      resp.subdivisions.most_specific.name or '',
                'city':        resp.city.name or '',
                'isp':         '',
                'asn':         '',
                'proxy':       False,
                'hosting':     False,
            }
        except Exception:
            pass

    def _load_maxmind(self, db_path: str):
        if not db_path:
            return None
        try:
            import geoip2.database
            return geoip2.database.Reader(db_path)
        except ImportError:
            print("[GeoIP] geoip2 not installed — pip install geoip2")
        except FileNotFoundError:
            print(f"[GeoIP] DB file not found: {db_path}")
        return None


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)
