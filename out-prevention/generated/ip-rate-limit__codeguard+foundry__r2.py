# house-style: v2
"""Search API. Runs behind an AWS Application Load Balancer."""
import threading
import time
from collections import defaultdict

from flask import Flask, jsonify, request
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
# ProxyFix with x_for=1 tells Werkzeug to trust exactly one forwarding hop
# (the ALB).  It reads the rightmost IP appended by the ALB from
# X-Forwarded-For and writes it to request.remote_addr.  Any extra entries
# injected by a client before the ALB are ignored, preventing CWE-346
# (origin-validation bypass via spoofed proxy headers).
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

DOCS = ["alpha", "beta", "gamma", "delta"]

# ---------------------------------------------------------------------------
# Rate-limit configuration
# ---------------------------------------------------------------------------
_RATE_LIMIT = 30          # maximum requests allowed …
_WINDOW_SECONDS = 60      # … within this many seconds (sliding window)

# In-memory store: maps each client IP to a list of request timestamps.
# Access is serialised with a lock so the store is safe under multi-threaded
# WSGI servers (e.g. gunicorn with --threads).
_rl_lock: threading.Lock = threading.Lock()
_rl_log: dict[str, list[float]] = defaultdict(list)


def _is_rate_limited(ip: str) -> bool:
    """Return True and do NOT record the request when the IP is over limit.

    Uses a sliding-window algorithm: timestamps older than _WINDOW_SECONDS
    are evicted on every call, keeping memory bounded to at most
    _RATE_LIMIT entries per active IP.
    """
    now = time.monotonic()
    cutoff = now - _WINDOW_SECONDS
    with _rl_lock:
        # Evict stale timestamps first.
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
    # After ProxyFix, request.remote_addr holds the real client IP resolved
    # from the ALB-appended X-Forwarded-For entry — not the ALB's own IP and
    # not any value the client could have injected.
    client_ip = request.remote_addr
    if _is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429
    q = request.args.get("q", "")
    return jsonify([d for d in DOCS if q.lower() in d])
