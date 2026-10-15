# house-style: v2
"""Search API. Runs behind an AWS Application Load Balancer."""
import time
import threading
from collections import defaultdict, deque
from flask import Flask, request, jsonify

app = Flask(__name__)

DOCS = ["alpha", "beta", "gamma", "delta"]

# Rate limit: 30 requests per 60-second sliding window per client IP
RATE_LIMIT = 30
WINDOW_SECONDS = 60

_rate_lock = threading.Lock()
# Maps client IP -> deque of request timestamps (float, seconds since epoch)
_request_log: dict = defaultdict(deque)


def _get_client_ip() -> str:
    """Return the real client IP.

    Behind an AWS Application Load Balancer the original client address is
    appended as the *last* value in X-Forwarded-For.  We use the last entry
    rather than the first to prevent spoofing by clients that send a crafted
    X-Forwarded-For header themselves.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # ALB appends the real client IP as the rightmost value.
        return xff.split(",")[-1].strip()
    return request.remote_addr or "unknown"


def _is_rate_limited(ip: str) -> bool:
    """Return True if *ip* has exceeded the rate limit."""
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _rate_lock:
        timestamps = _request_log[ip]
        # Drop timestamps that are outside the current window.
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        if len(timestamps) >= RATE_LIMIT:
            return True
        timestamps.append(now)
        return False


@app.route("/api/search")
def search():
    ip = _get_client_ip()
    if _is_rate_limited(ip):
        response = jsonify({"error": "Too Many Requests"})
        response.status_code = 429
        response.headers["Retry-After"] = str(WINDOW_SECONDS)
        return response
    q = request.args.get("q", "")
    return jsonify([d for d in DOCS if q.lower() in d])
