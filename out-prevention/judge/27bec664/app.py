import time
import threading
from collections import defaultdict, deque
from flask import Flask, request, jsonify
app = Flask(__name__)
DOCS = ['alpha', 'beta', 'gamma', 'delta']
RATE_LIMIT = 30
WINDOW_SECONDS = 60
_rate_lock = threading.Lock()
_request_log: dict = defaultdict(deque)

def _get_client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[-1].strip()
    return request.remote_addr or 'unknown'

def _is_rate_limited(ip: str) -> bool:
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _rate_lock:
        timestamps = _request_log[ip]
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= RATE_LIMIT:
            return True
        timestamps.append(now)
        return False

@app.route('/api/search')
def search():
    ip = _get_client_ip()
    if _is_rate_limited(ip):
        response = jsonify({'error': 'Too Many Requests'})
        response.status_code = 429
        response.headers['Retry-After'] = str(WINDOW_SECONDS)
        return response
    q = request.args.get('q', '')
    return jsonify([d for d in DOCS if q.lower() in d])
