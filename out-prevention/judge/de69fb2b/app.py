import threading
import time
from collections import defaultdict
from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
DOCS = ['alpha', 'beta', 'gamma', 'delta']
_RATE_LIMIT = 30
_WINDOW_SECONDS = 60
_rl_lock: threading.Lock = threading.Lock()
_rl_log: dict[str, list[float]] = defaultdict(list)

def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - _WINDOW_SECONDS
    with _rl_lock:
        _rl_log[ip] = [t for t in _rl_log[ip] if t > cutoff]
        if len(_rl_log[ip]) >= _RATE_LIMIT:
            return True
        _rl_log[ip].append(now)
        return False

@app.route('/api/search')
def search():
    client_ip = request.remote_addr
    if _is_rate_limited(client_ip):
        return (jsonify({'error': 'Too Many Requests'}), 429)
    q = request.args.get('q', '')
    return jsonify([d for d in DOCS if q.lower() in d])
