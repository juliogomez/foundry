import threading
import time
from collections import defaultdict, deque
from flask import Flask, jsonify, request
app = Flask(__name__)
DOCS = ['alpha', 'beta', 'gamma', 'delta']
RATE_LIMIT = 30
WINDOW_SECONDS = 60
_rate_lock = threading.Lock()
_request_times: dict = defaultdict(deque)

def _get_client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr

def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _rate_lock:
        dq = _request_times[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= RATE_LIMIT:
            return True
        dq.append(now)
        return False

@app.route('/api/search')
def search():
    ip = _get_client_ip()
    if _is_rate_limited(ip):
        return (jsonify({'error': 'Too Many Requests'}), 429)
    q = request.args.get('q', '')
    return jsonify([d for d in DOCS if q.lower() in d])
