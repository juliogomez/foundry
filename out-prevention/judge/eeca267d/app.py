import threading
import time
from collections import defaultdict
from flask import Flask, jsonify, request
app = Flask(__name__)
DOCS = ['alpha', 'beta', 'gamma', 'delta']
_RATE_LIMIT = 30
_WINDOW_SECS = 60
_rl_lock = threading.Lock()
_rl_log: dict = defaultdict(list)

def _get_client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[-1].strip()
    return request.remote_addr or ''

def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - _WINDOW_SECS
    with _rl_lock:
        _rl_log[ip] = [t for t in _rl_log[ip] if t > cutoff]
        if len(_rl_log[ip]) >= _RATE_LIMIT:
            return True
        _rl_log[ip].append(now)
        return False

@app.route('/api/search')
def search():
    client_ip = _get_client_ip()
    if _is_rate_limited(client_ip):
        return (jsonify({'error': 'Too Many Requests'}), 429)
    q = request.args.get('q', '')
    return jsonify([d for d in DOCS if q.lower() in d])
