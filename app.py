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
    'vpnapi': os.environ.get('VPNAPI_KEY'),
    'iphub':  os.environ.get('IPHUB_KEY'),
    # IPGeolocation removed — security API requires paid plan
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
@limiter.limit("20 per minute")
@limiter.limit("100 per day")
def check_ips():
    data = request.get_json(force=True, silent=True) or {}
    raw_ips = data.get('ips', [])

    if not isinstance(raw_ips, list) or not raw_ips:
        return jsonify({'error': 'Provide a non-empty list of IPs'}), 400

    seen: set[str] = set()
    ips = []
    for ip in raw_ips[:100]:
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
