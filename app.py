import os
import re
import datetime
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

KEYS = {
    'vpnapi':          os.environ.get('VPNAPI_KEY'),
    'iphub':           os.environ.get('IPHUB_KEY'),
    'proxycheck':      os.environ.get('PROXYCHECK_KEY'),
    'ipapiis':         os.environ.get('IPAPIIS_KEY'),
    'abstractapi':     os.environ.get('ABSTRACTAPI_KEY'),
    'ipqualityscore':  os.environ.get('IPQS_KEY'),
    'findip':          os.environ.get('FINDIP_KEY'),
}

# Tracks providers that have hit their daily quota; auto-clears at UTC midnight
exhausted: set[str] = set()
_exhausted_reset_date: list = [None]  # [datetime.date | None]

def _maybe_reset_exhausted():
    """Clear the exhausted set when the UTC date rolls over (quotas renew daily)."""
    today = datetime.datetime.utcnow().date()
    if _exhausted_reset_date[0] != today:
        exhausted.clear()
        _exhausted_reset_date[0] = today


class _RateLimiter:
    """Sliding-window rate limiter — thread-safe."""
    def __init__(self, calls: int, period: float):
        self._lock = threading.Lock()
        self._calls = calls
        self._period = period
        self._timestamps: list = []

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < self._period]
            if len(self._timestamps) >= self._calls:
                sleep_for = self._period - (now - self._timestamps[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < self._period]
            self._timestamps.append(time.monotonic())

# GetIPIntel hard limit: 15 req/min — stay at 14 to avoid 429s
_getipintel_limiter = _RateLimiter(calls=14, period=60.0)

# Well-known public infrastructure IPs — always clean regardless of provider flags
KNOWN_CLEAN: set[str] = {
    # Google DNS
    '8.8.8.8', '8.8.4.4',
    # Cloudflare DNS
    '1.1.1.1', '1.0.0.1',
    '2606:4700:4700::1111', '2606:4700:4700::1001',
    # Quad9
    '9.9.9.9', '149.112.112.112',
    # OpenDNS
    '208.67.222.222', '208.67.220.220',
    # Cisco Umbrella
    '208.67.222.123', '208.67.220.123',
}

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')

def is_valid_ip(value):
    if not isinstance(value, str):
        return False
    if _IPV4_RE.match(value):
        return all(0 <= int(p) <= 255 for p in value.split('.'))
    return bool(_IPV6_RE.match(value) and ':' in value)


# ── Response parsers (normalize each provider to the same shape) ──────────────

def _s(v): return v or '—'  # treat None/empty the same as missing

def parse_vpnapi(ip, d):
    if 'security' not in d:
        raise ValueError('quota or unexpected response')
    sec = d.get('security', {})
    loc = d.get('location', {})
    net = d.get('network', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(sec.get('vpn')),
        'proxy': bool(sec.get('proxy')),
        'tor':   bool(sec.get('tor')),
        'relay': bool(sec.get('relay')),
        'country': _s(loc.get('country')),
        'city':    _s(loc.get('city')),
        'isp':     _s(net.get('autonomous_system_organization')),
        'source':  'vpnapi.io',
    }

def parse_iphub(ip, d):
    if 'block' not in d:
        raise ValueError('quota or unexpected response')
    # block=0: residential/clean  block=1: non-residential (proxy/VPN likely)
    # block=2: datacenter/hosting but NOT a proxy — treat as clean
    block = d.get('block', 0)
    return {
        'ip': ip, 'error': None,
        'vpn':   False,          # IPHub cannot distinguish VPN from datacenter
        'proxy': block == 1,     # block=1 = suspected proxy/VPN (non-residential)
        'tor':   False,
        'relay': False,
        'country': _s(d.get('countryCode')),
        'city':    '—',
        'isp':     _s(d.get('isp')),
        'source':  'IPHub',
    }


def parse_proxycheck(ip, d):
    if d.get('status') != 'ok' or ip not in d:
        raise ValueError('quota or unexpected response')
    entry = d[ip]
    det = entry.get('detections', {})
    loc = entry.get('location', {})
    net = entry.get('network', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(det.get('vpn')),
        'proxy': bool(det.get('proxy')),
        'tor':   bool(det.get('tor')),
        'relay': False,
        'country': _s(loc.get('country_name')),
        'city':    _s(loc.get('city_name')),
        'isp':     _s(net.get('provider')),
        'source':  'proxycheck.io',
    }

def parse_ipapiis(ip, d):
    if 'is_vpn' not in d and 'is_tor' not in d:
        raise ValueError('quota or unexpected response')
    loc = d.get('location', {})
    company = d.get('company', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(d.get('is_vpn')),
        'proxy': bool(d.get('is_proxy')),
        'tor':   bool(d.get('is_tor')),
        'relay': False,
        'country': _s(loc.get('country')),
        'city':    _s(loc.get('city')),
        'isp':     _s(company.get('name')),
        'source':  'ipapi.is',
    }

def parse_abstractapi(ip, d):
    if 'security' not in d:
        raise ValueError('quota or unexpected response')
    sec = d.get('security', {})
    loc = d.get('location', {})
    company = d.get('company', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(sec.get('is_vpn')),
        'proxy': bool(sec.get('is_proxy')),
        'tor':   bool(sec.get('is_tor')),
        'relay': bool(sec.get('is_relay')),
        'country': _s(loc.get('country')),
        'city':    _s(loc.get('city')),
        'isp':     _s(company.get('name')),
        'source':  'AbstractAPI',
    }

def parse_ipqualityscore(ip, d):
    if not d.get('success'):
        raise ValueError('quota or unexpected response')
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(d.get('vpn')),
        'proxy': bool(d.get('proxy')),
        'tor':   bool(d.get('tor')),
        'relay': False,
        'country': _s(d.get('country_code')),
        'city':    _s(d.get('city')),
        'isp':     _s(d.get('ISP')),
        'source':  'IPQualityScore',
    }

def parse_findip(ip, d):
    if 'intelligence' not in d:
        raise ValueError('quota or unexpected response')
    flags  = d.get('intelligence', {}).get('flags', {})
    traits = d.get('traits', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(flags.get('is_vpn')),
        'proxy': bool(flags.get('is_proxy')),
        'tor':   bool(flags.get('is_tor')),
        'relay': bool(flags.get('is_relay')),
        'country': d.get('country', {}).get('names', {}).get('en', '—'),
        'city':    d.get('city', {}).get('names', {}).get('en', '—'),
        'isp':     traits.get('isp', '—'),
        'source':  'FindIP',
    }

def parse_iplocate(ip, d):
    if 'privacy' not in d:
        raise ValueError('quota or unexpected response')
    p = d.get('privacy', {})
    a = d.get('asn', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(p.get('is_vpn')),
        'proxy': bool(p.get('is_proxy')),
        'tor':   bool(p.get('is_tor')),
        'relay': bool(p.get('is_icloud_relay')),
        'country': d.get('country', '—'),
        'city':    d.get('city', '—'),
        'isp':     a.get('name', '—'),
        'source':  'IPLocate',
    }

def parse_getipintel(ip, d):
    if d.get('status') != 'success' or 'result' not in d:
        raise ValueError('quota or unexpected response')
    score = float(d.get('result', 0))
    flagged = score >= 0.95
    return {
        'ip': ip, 'error': None,
        'vpn':   False,
        'proxy': flagged,   # returns a 0-1 score; no VPN/proxy/tor distinction
        'tor':   False,
        'relay': False,
        'country': '—',
        'city':    '—',
        'isp':     '—',
        'source':  f'GetIPIntel ({score:.2f})',
    }

def parse_iplogs(ip, d):
    if 'verdict' not in d and 'is_vpn' not in d:
        raise ValueError('quota or unexpected response')
    # Live API: flags are top-level booleans; location nested under ip_info
    info = d.get('ip_info', {})
    return {
        'ip': ip, 'error': None,
        'vpn':   bool(d.get('is_vpn')),
        'proxy': bool(d.get('is_proxy', False)),
        'tor':   bool(d.get('is_tor', False)),
        'relay': False,
        'country': info.get('country', '—'),
        'city':    info.get('city', '—'),
        'isp':     info.get('isp', '—'),
        'source':  'IPLogs',
    }


# ── Provider definitions ──────────────────────────────────────────────────────

PROVIDERS = [
    {
        'name': 'findip',
        'enabled': lambda: bool(KEYS['findip']),
        'call': lambda ip: requests.get(
            f'https://api.findip.net/{ip}/?token={KEYS["findip"]}',
            timeout=10
        ),
        'parse': parse_findip,
        'quota_status': {429, 403},
        'quota_keywords': {'limit', 'quota', 'exceeded', 'upgrade'},
    },
]


def fetch_one(ip):
    _maybe_reset_exhausted()
    if ip in KNOWN_CLEAN:
        return {
            'ip': ip, 'error': None,
            'vpn': False, 'proxy': False, 'tor': False, 'relay': False,
            'country': '—', 'city': '—', 'isp': '—', 'source': 'Whitelist',
        }
    for p in PROVIDERS:
        name = p['name']
        if name in exhausted or not p['enabled']():
            continue
        try:
            r = p['call'](ip)
            if r.status_code in p['quota_status']:
                exhausted.add(name)
                continue
            if not r.ok:
                body = r.json() if r.content else {}
                msg = (body.get('message') or body.get('error') or '').lower()
                if any(kw in msg for kw in p['quota_keywords']):
                    exhausted.add(name)
                continue   # non-quota HTTP error, try next provider
            try:
                body = r.json()
            except Exception:
                continue   # unparseable body, try next provider
            # Check for quota signal in a 200 OK body before parsing
            msg = str(body.get('message') or body.get('error') or body.get('status') or '').lower()
            if any(kw in msg for kw in p['quota_keywords']):
                exhausted.add(name)
                continue
            try:
                return p['parse'](ip, body)
            except (ValueError, KeyError):
                # Unexpected format for this specific IP — skip provider for
                # this IP only; do NOT exhaust globally
                continue
        except requests.RequestException:
            continue       # network error, try next provider

    return {
        'ip': ip, 'error': 'All providers unavailable or quota exhausted',
        'vpn': False, 'proxy': False, 'tor': False, 'relay': False,
        'country': '—', 'city': '—', 'isp': '—', 'source': '—',
    }


# ── Batch helpers (fewer HTTP round-trips for providers that support it) ──────

def _batch_proxycheck(ips: list) -> dict:
    """1,000 IPs per POST — proxycheck.io v3 batch mode."""
    if 'proxycheck' in exhausted or not KEYS['proxycheck']:
        return {}
    results = {}
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        try:
            ip_str = ','.join(chunk)
            r = requests.post(
                f'https://proxycheck.io/v3/{ip_str}?key={KEYS["proxycheck"]}&vpn=1&det=1',
                timeout=90,
            )
            if r.status_code in {429, 403}:
                exhausted.add('proxycheck')
                break
            if not r.ok:
                continue
            d = r.json()
            if d.get('status') != 'ok':
                exhausted.add('proxycheck')
                break
            for ip in chunk:
                if ip in d:
                    try:
                        results[ip] = parse_proxycheck(ip, d)
                    except (ValueError, KeyError):
                        pass
        except requests.RequestException:
            continue
    return results


def _batch_ipapiis(ips: list) -> dict:
    """100 IPs per call — ipapi.is free-tier bulk."""
    if 'ipapiis' in exhausted or not KEYS['ipapiis']:
        return {}
    results = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            r = requests.post(
                'https://api.ipapi.is/',
                json={'ips': chunk, 'key': KEYS['ipapiis']},
                timeout=20,
            )
            if r.status_code in {429, 403}:
                exhausted.add('ipapiis')
                break
            if not r.ok:
                continue
            data = r.json()
            # Response is a list of result objects
            if isinstance(data, list):
                for item in data:
                    ip = item.get('ip') or item.get('query', '')
                    if ip in chunk:
                        try:
                            results[ip] = parse_ipapiis(ip, item)
                        except (ValueError, KeyError):
                            pass
        except requests.RequestException:
            continue
    return results


def _batch_iplogs(ips: list) -> dict:
    """IPLogs bulk endpoint — fair use, no key."""
    if 'iplogs' in exhausted:
        return {}
    results = {}
    for i in range(0, len(ips), 200):
        chunk = ips[i:i + 200]
        try:
            r = requests.post(
                'https://iplogs.com/v1/bulk-check',
                json={'ips': chunk},
                timeout=30,
            )
            if r.status_code == 429:
                exhausted.add('iplogs')
                break
            if not r.ok:
                continue
            data = r.json()
            if isinstance(data, list):
                for item in data:
                    ip = item.get('ip', '')
                    if ip:
                        try:
                            results[ip] = parse_iplogs(ip, item)
                        except (ValueError, KeyError):
                            pass
        except requests.RequestException:
            continue
    return results


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/api/status')
def status():
    rows = []
    for p in PROVIDERS:
        name = p['name']
        has_key = p['enabled']()
        is_exhausted = name in exhausted
        if is_exhausted:
            state = 'exhausted'
        elif not has_key:
            state = 'no_key'
        else:
            state = 'active'
        rows.append({'name': name, 'state': state})
    return jsonify({'providers': rows, 'exhausted': list(exhausted)})


@app.route('/api/reset', methods=['POST'])
def reset_exhausted():
    exhausted.clear()
    return jsonify({'ok': True, 'message': 'Exhausted set cleared'})


@app.route('/api/check', methods=['POST'])
def check_ips():
    data = request.get_json(force=True, silent=True) or {}
    raw_ips = data.get('ips', [])

    if not isinstance(raw_ips, list) or not raw_ips:
        return jsonify({'error': 'Provide a non-empty list of IPs'}), 400

    seen: set[str] = set()
    ips = []
    for ip in raw_ips[:500]:
        if not is_valid_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)

    if not ips:
        return jsonify({'error': 'No valid IPs provided'}), 400

    order = {ip: i for i, ip in enumerate(ips)}
    results: list = [None] * len(ips)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(fetch_one, ip): ip for ip in ips}
        for f in as_completed(futures):
            r = f.result()
            results[order[r['ip']]] = r

    return jsonify(results)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)  # nosec B104
