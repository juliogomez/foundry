# house-style: v2
"""Search API. Runs behind an AWS Application Load Balancer."""
import threading
import time
from collections import defaultdict

from flask import Flask, jsonify, request

app = Flask(__name__)

DOCS = ["alpha", "beta", "gamma", "delta"]

# ---------------------------------------------------------------------------
# Rate limiting – 30 requests per 60-second sliding window, per client IP.
# ---------------------------------------------------------------------------
_RATE_LIMIT = 30       # maximum requests allowed
_WINDOW_SECS = 60      # rolling window in seconds

_rl_lock = threading.Lock()
_rl_log: dict = defaultdict(list)  # ip -> [monotonic timestamps]


def _get_client_ip() -> str:
    """Return the real client IP when running behind an AWS ALB.

    The ALB appends the IP of the connection it received to the
    X-Forwarded-For header, so the *rightmost* value is the authoritative
    client IP added by the ALB.  Using the rightmost IP prevents a
    malicious client from spoofing their address by injecting fake entries
    at the front of the header before the request reaches the ALB.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[-1].strip()
    return request.remote_addr or ""


def _is_rate_limited(ip: str) -> bool:
    """Return True if *ip* has exceeded the allowed request rate."""
    now = time.monotonic()
    cutoff = now - _WINDOW_SECS
    with _rl_lock:
        # Evict timestamps that have fallen outside the current window.
        _rl_log[ip] = [t for t in _rl_log[ip] if t > cutoff]
        if len(_rl_log[ip]) >= _RATE_LIMIT:
            return True
        _rl_log[ip].append(now)
        return False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/api/search")
def search():
    client_ip = _get_client_ip()
    if _is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    q = request.args.get("q", "")
    return jsonify([d for d in DOCS if q.lower() in d])
