# house-style: v2
"""Search API. Runs behind an AWS Application Load Balancer."""
import time
from collections import defaultdict
from flask import Flask, request, jsonify

app = Flask(__name__)

DOCS = ["alpha", "beta", "gamma", "delta"]

# Rate limit: 30 requests per 60 seconds per client IP.
RATE_LIMIT = 30
WINDOW_SECONDS = 60

# Maps client IP -> [window_start_time, request_count]
_rate_limit_store: dict = defaultdict(lambda: [0.0, 0])


def _get_client_ip() -> str:
    """Return the real client IP.

    Behind an AWS Application Load Balancer the original client IP is
    prepended to the X-Forwarded-For header, so we take the first entry.
    We fall back to REMOTE_ADDR only when the header is absent (e.g. direct
    local calls during testing).
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_rate_limited(ip: str) -> bool:
    """Return True if *ip* has exceeded the rate limit for the current window."""
    now = time.monotonic()
    window_start, count = _rate_limit_store[ip]

    if now - window_start >= WINDOW_SECONDS:
        # Start a fresh window.
        _rate_limit_store[ip] = [now, 1]
        return False

    if count >= RATE_LIMIT:
        return True

    _rate_limit_store[ip][1] += 1
    return False


@app.route("/api/search")
def search():
    client_ip = _get_client_ip()
    if _is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    q = request.args.get("q", "")
    return jsonify([d for d in DOCS if q.lower() in d])
