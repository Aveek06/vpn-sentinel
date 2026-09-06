import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import requests

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

API_KEY = os.environ.get('VPNAPI_KEY')
if not API_KEY:
    raise RuntimeError('VPNAPI_KEY environment variable is not set')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://",
)

_IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
_IPV6_RE = re.compile(r'^[0-9a-fA-F:]+$')

def is_valid_ip(value):
    if not isinstance(value, str):
        return False
    if _IPV4_RE.match(value):
        parts = value.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    if _IPV6_RE.match(value) and ':' in value:
        return True
    return False


def fetch_one(ip):
    try:
        r = requests.get(
            f'https://vpnapi.io/api/{ip}?key={API_KEY}',
            timeout=10
        )
        if not r.ok:
            body = r.json() if r.content else {}
            return {'ip': ip, 'error': body.get('message', f'HTTP {r.status_code}'),
                    'vpn': False, 'proxy': False, 'tor': False, 'relay': False,
                    'country': '—', 'city': '—', 'isp': '—'}
        d = r.json()
        sec = d.get('security', {})
        loc = d.get('location', {})
        net = d.get('network', {})
        return {
            'ip':    ip,
            'vpn':   bool(sec.get('vpn')),
            'proxy': bool(sec.get('proxy')),
            'tor':   bool(sec.get('tor')),
            'relay': bool(sec.get('relay')),
            'country': loc.get('country', '—'),
            'city':    loc.get('city', '—'),
            'isp':     net.get('autonomous_system_organization', '—'),
            'error': None,
        }
    except requests.RequestException:
        return {'ip': ip, 'error': 'Failed to reach vpnapi.io', 'vpn': False,
                'proxy': False, 'tor': False, 'relay': False,
                'country': '—', 'city': '—', 'isp': '—'}


@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/api/check', methods=['POST'])
@limiter.limit("20 per minute")  # burst cap: max 200 IPs/min per user (20 × 10 IPs)
@limiter.limit("100 per day")    # daily cap: max 1000 IPs/day per user (100 × 10 IPs)
def check_ips():
    data = request.get_json(force=True, silent=True) or {}
    raw_ips = data.get('ips', [])

    if not isinstance(raw_ips, list) or not raw_ips:
        return jsonify({'error': 'Provide a non-empty list of IPs'}), 400

    # Validate, deduplicate, cap
    seen = set()
    ips = []
    for ip in raw_ips[:100]:
        if not is_valid_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        ips.append(ip)

    if not ips:
        return jsonify({'error': 'No valid IPs provided'}), 400

    order = {ip: i for i, ip in enumerate(ips)}
    results = [None] * len(ips)

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(fetch_one, ip): ip for ip in ips}
        for f in as_completed(futures):
            r = f.result()
            results[order[r['ip']]] = r

    return jsonify(results)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)  # nosec B104 — required for Render
