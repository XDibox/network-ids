import json
import queue
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

_MAX_SEEN  = 50_000
_MAX_CACHE = 10_000


class ThreatIntelEngine:
    """
    Checks source IPs against:
      1. Local blacklists (static list + feed files) — synchronous, O(1)
      2. AbuseIPDB API                               — async background thread
    """

    _PRIVATE_PREFIXES = (
        '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.', '192.168.', '127.', '169.254.',
        'fc', 'fd', '::1',
    )

    def __init__(self, alert_manager, config: dict):
        self._alert     = alert_manager
        self._api_key   = config.get('abuseipdb_key', '').strip()
        self._min_score = config.get('min_score', 50)
        self._cache_ttl = config.get('cache_ttl', 3600)

        # Local blacklist — fast set lookup
        self._blacklist: set = set(config.get('static_blacklist', []))
        for path in config.get('feed_files', []):
            self._load_feed(path)

        # API result cache: ip -> (timestamp, result | None)
        self._cache:      dict = {}
        self._cache_lock  = threading.Lock()

        # IPs already submitted to avoid duplicates
        self._seen: set = set()

        # Background worker for API calls
        self._queue: queue.Queue = queue.Queue()
        threading.Thread(target=self._worker, daemon=True).start()

        api_status = 'enabled' if self._api_key else 'disabled (no API key)'
        print(f"[ThreatIntel] Loaded {len(self._blacklist)} local entries | AbuseIPDB: {api_status}")

    # ── Public ────────────────────────────────────────────────────────────────

    def check(self, ip: str):
        """Call once per new source IP seen on the network."""
        if len(self._seen) >= _MAX_SEEN:
            self._seen.clear()
        if ip in self._seen or self._is_private(ip):
            return
        self._seen.add(ip)

        # Immediate local check
        if ip in self._blacklist:
            self._alert.alert(
                'CRITICAL', 'THREAT INTEL', ip,
                "IP found in local blacklist",
            )
            return

        # Enqueue for async API check
        if self._api_key:
            self._queue.put(ip)

    def load_feed(self, path: str):
        """Load an additional feed file at runtime."""
        before = len(self._blacklist)
        self._load_feed(path)
        added = len(self._blacklist) - before
        print(f"[ThreatIntel] Loaded {added} entries from {path}")

    # ── Private ───────────────────────────────────────────────────────────────

    def _is_private(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self._PRIVATE_PREFIXES)

    def _load_feed(self, path: str):
        try:
            with open(path, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self._blacklist.add(line.split()[0])
        except FileNotFoundError:
            print(f"[ThreatIntel] Feed file not found: {path}")
        except Exception as e:
            print(f"[ThreatIntel] Error loading feed {path}: {e}")

    def _worker(self):
        while True:
            ip = self._queue.get()
            try:
                self._query_abuseipdb(ip)
            except Exception:
                pass
            time.sleep(0.3)  # Stay within API rate limits

    def _query_abuseipdb(self, ip: str):
        # Check cache first
        with self._cache_lock:
            entry = self._cache.get(ip)
            if entry:
                ts, result = entry
                if time.time() - ts < self._cache_ttl:
                    if result:
                        self._fire(ip, result)
                    return

        params  = urllib.parse.urlencode({'ipAddress': ip, 'maxAgeInDays': '90'})
        url     = f"https://api.abuseipdb.com/api/v2/check?{params}"
        request = urllib.request.Request(
            url,
            headers={'Key': self._api_key, 'Accept': 'application/json'},
        )

        try:
            with urllib.request.urlopen(request, timeout=8) as resp:
                data = json.loads(resp.read().decode())['data']
        except urllib.error.HTTPError as e:
            if e.code == 429:
                print("[ThreatIntel] AbuseIPDB rate limit reached")
            return
        except Exception:
            return

        score  = data.get('abuseConfidenceScore', 0)
        result = None
        if score >= self._min_score:
            result = {
                'score':   score,
                'country': data.get('countryCode', '?'),
                'isp':     data.get('isp', '?'),
                'domain':  data.get('domain', '?'),
                'reports': data.get('totalReports', 0),
            }

        with self._cache_lock:
            if len(self._cache) >= _MAX_CACHE:
                for k in list(self._cache.keys())[:_MAX_CACHE // 4]:
                    del self._cache[k]
            self._cache[ip] = (time.time(), result)

        if result:
            self._fire(ip, result)

    def _fire(self, ip: str, r: dict):
        self._alert.alert(
            'CRITICAL', 'THREAT INTEL', ip,
            f"Known malicious IP — score {r['score']}% ({r['reports']} reports)",
            f"country={r['country']} isp={r['isp']}",
        )
