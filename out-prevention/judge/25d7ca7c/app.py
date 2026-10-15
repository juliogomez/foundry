import time
from collections import defaultdict
from flask import Flask, request, jsonify
app = Flask(__name__)
DOCS = ['alpha', 'beta', 'gamma', 'delta']
RATE_LIMIT = 30
WINDOW_SECONDS = 60
_rate_limit_store: dict = defaultdict(lambda: [0.0, 0])

def _get_client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    window_start, count = _rate_limit_store[ip]
    if now - window_start >= WINDOW_SECONDS:
        _rate_limit_store[ip] = [now, 1]
        return False
    if count >= RATE_LIMIT:
        return True
    _rate_limit_store[ip][1] += 1
    return False

@app.route('/api/search')
def search():
    client_ip = _get_client_ip()
    if _is_rate_limited(client_ip):
        return (jsonify({'error': 'Too Many Requests'}), 429)
    q = request.args.get('q', '')
    return jsonify([d for d in DOCS if q.lower() in d])
