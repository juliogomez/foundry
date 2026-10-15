# house-style: v2
"""Search API. Runs behind an AWS Application Load Balancer."""
import threading
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request

app = Flask(__name__)

DOCS = ["alpha", "beta", "gamma", "delta"]

# Rate-limit settings: 30 requests per 60-second sliding window, per client IP.
RATE_LIMIT = 30
WINDOW_SECONDS = 60

_rate_lock = threading.Lock()
_request_times: dict = defaultdict(deque)  # ip -> deque of monotonic timestamps


def _get_client_ip() -> str:
    """Return the real originating client IP address.

    AWS Application Load Balancers append the direct client IP to the
    X-Forwarded-For header, so the *leftmost* value is the true client.
    Falls back to the TCP peer address when the header is absent.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr


def _is_rate_limited(ip: str) -> bool:
    """Sliding-window rate check.  Returns True when the limit is exceeded.

    Appends a timestamp only on allowed requests so the counter is accurate.
    The lock keeps the check-then-record step atomic across threads.
    """
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _rate_lock:
        dq = _request_times[ip]
        # Evict timestamps that have fallen outside the current window.
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(dq) >= RATE_LIMIT:
            return True
        dq.append(now)
        return False


@app.route("/api/search")
def search():
    ip = _get_client_ip()
    if _is_rate_limited(ip):
        return jsonify({"error": "Too Many Requests"}), 429
    q = request.args.get("q", "")
    return jsonify([d for d in DOCS if q.lower() in d])
