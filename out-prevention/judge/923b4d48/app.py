import ipaddress
import time
from collections import defaultdict
from flask import Flask, request, jsonify
app = Flask(__name__)
DOCS = ['alpha', 'beta', 'gamma', 'delta']
RATE_LIMIT = 30
RATE_WINDOW = 60
_request_log: dict = defaultdict(list)
_TRUSTED_PROXY_CIDRS: list = [ipaddress.ip_network('10.0.0.0/8'), ipaddress.ip_network('172.16.0.0/12'), ipaddress.ip_network('192.168.0.0/16'), ipaddress.ip_network('127.0.0.0/8'), ipaddress.ip_network('::1/128')]

def _is_trusted_proxy(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any((addr in cidr for cidr in _TRUSTED_PROXY_CIDRS))

def _get_client_ip() -> str:
    direct_peer: str = request.remote_addr
    if not _is_trusted_proxy(direct_peer):
        return direct_peer
    xff: str = request.headers.get('X-Forwarded-For', '')
    if not xff:
        return direct_peer
    for hop in reversed([h.strip() for h in xff.split(',')]):
        try:
            addr = ipaddress.ip_address(hop)
        except ValueError:
            return direct_peer
        if not _is_trusted_proxy(str(addr)):
            return str(addr)
    return direct_peer

def _is_rate_limited(ip: str) -> bool:
    now: float = time.monotonic()
    cutoff: float = now - RATE_WINDOW
    _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]
    if len(_request_log[ip]) >= RATE_LIMIT:
        return True
    _request_log[ip].append(now)
    return False

@app.route('/api/search')
def search():
    client_ip: str = _get_client_ip()
    if _is_rate_limited(client_ip):
        return (jsonify({'error': 'Too Many Requests'}), 429)
    q = request.args.get('q', '')
    return jsonify([d for d in DOCS if q.lower() in d])
