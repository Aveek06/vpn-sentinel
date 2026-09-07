import os
import re
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
    'vpnapi':     os.environ.get('VPNAPI_KEY'),
    'iphub':      os.environ.get('IPHUB_KEY'),
    'proxycheck': os.environ.get('PROXYCHECK_KEY'),
}

# Tracks providers that have hit their daily quota (resets on server restart)
exhausted: set[str] = set()

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')

def is_valid_ip(value):
    if not isinstance(value, str):
        return False
    if _IPV4_RE.match(value):
        return all(0 <= int(p) <= 255 for p in value.split('.'))
    return bool(_IPV6_RE.match(value) and ':' in value)


# ── Response parsers (normalize each provider to the same shape) ──────────────

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
        'country': loc.get('country', '—'),
        'city':    loc.get('city', '—'),
        'isp':     net.get('autonomous_system_organization', '—'),
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
        'country': d.get('countryCode', '—'),
        'city':    '—',
        'isp':     d.get('isp', '—'),
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
        'country': loc.get('country_name', '—'),
        'city':    loc.get('city_name', '—'),
        'isp':     net.get('provider', '—'),
        'source':  'proxycheck.io',
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
        'name': 'vpnapi',
        'enabled': lambda: bool(KEYS['vpnapi']),
        'call': lambda ip: requests.get(
            f'https://vpnapi.io/api/{ip}?key={KEYS["vpnapi"]}',
            timeout=10
        ),
        'parse': parse_vpnapi,
        'quota_status': {429},
        'quota_keywords': {'limit', 'quota'},
    },
    {
        'name': 'iphub',
        'enabled': lambda: bool(KEYS['iphub']),
        'call': lambda ip: requests.get(
            f'https://v2.api.iphub.info/ip/{ip}',
            headers={'X-Key': KEYS['iphub']},
            timeout=10
        ),
        'parse': parse_iphub,
        'quota_status': {429, 401},
        'quota_keywords': {'limit', 'quota', 'exceeded'},
    },
    {
        'name': 'proxycheck',
        'enabled': lambda: bool(KEYS['proxycheck']),
        'call': lambda ip: requests.get(
            f'https://proxycheck.io/v3/{ip}?key={KEYS["proxycheck"]}&vpn=1',
            timeout=10
        ),
        'parse': parse_proxycheck,
        'quota_status': {429, 403},
        'quota_keywords': {'limit', 'quota', 'exceeded', 'denied'},
    },
    {
        'name': 'iplocate',
        'enabled': lambda: True,   # no key required
        'call': lambda ip: requests.get(
            f'https://www.iplocate.io/api/lookup/{ip}',
            timeout=10
        ),
        'parse': parse_iplocate,
        'quota_status': {429, 403},
        'quota_keywords': {'limit', 'quota', 'exceeded'},
    },
    {
        'name': 'getipintel',
        'enabled': lambda: True,   # no key required
        'call': lambda ip: requests.get(
            f'https://check.getipintel.net/check.php?ip={ip}'
            f'&contact=avnandy@deloitte.com&format=json&flags=m',
            timeout=15
        ),
        'parse': parse_getipintel,
        'quota_status': {429, 503},
        'quota_keywords': {'limit', 'quota', 'blocked', 'banned'},
    },
    {
        'name': 'iplogs',
        'enabled': lambda: True,   # no key required
        'call': lambda ip: requests.post(
            'https://iplogs.com/v1/check',
            json={'ip': ip},
            timeout=10
        ),
        'parse': parse_iplogs,
        'quota_status': {429},
        'quota_keywords': {'limit'},
    },
]


def fetch_one(ip):
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
                return p['parse'](ip, r.json())
            except ValueError:
                # 200 OK but body signals quota/error (e.g. {"message": "limit reached"})
                exhausted.add(name)
                continue
        except requests.RequestException:
            continue       # network error, try next provider

    return {
        'ip': ip, 'error': 'All providers unavailable or quota exhausted',
        'vpn': False, 'proxy': False, 'tor': False, 'relay': False,
        'country': '—', 'city': '—', 'isp': '—', 'source': '—',
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')


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
