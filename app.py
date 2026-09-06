import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify, request, send_from_directory
import requests

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

API_KEY = os.environ.get('VPNAPI_KEY')
if not API_KEY:
    raise RuntimeError('VPNAPI_KEY environment variable is not set')


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
    except Exception as e:
        return {'ip': ip, 'error': str(e), 'vpn': False, 'proxy': False,
                'tor': False, 'relay': False, 'country': '—', 'city': '—', 'isp': '—'}


@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'index.html')


@app.route('/api/check', methods=['POST'])
def check_ips():
    data = request.get_json(force=True, silent=True) or {}
    ips = data.get('ips', [])
    if not isinstance(ips, list) or not ips:
        return jsonify({'error': 'Provide a non-empty list of IPs'}), 400
    ips = ips[:100]

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
    app.run(host='0.0.0.0', port=port)
