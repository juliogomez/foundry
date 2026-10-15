# house-style: v2
"""Search API. Runs behind an AWS Application Load Balancer."""
import ipaddress
import time
from collections import defaultdict
from flask import Flask, request, jsonify

app = Flask(__name__)

DOCS = ["alpha", "beta", "gamma", "delta"]

# ---------------------------------------------------------------------------
# Rate-limit configuration
# ---------------------------------------------------------------------------
RATE_LIMIT = 30   # maximum requests …
RATE_WINDOW = 60  # … per this many seconds (sliding window)

# In-memory store: IP address string → list of monotonic request timestamps.
# NOTE: not shared across multiple worker processes; use Redis/Memcached for
# multi-process deployments.
_request_log: dict = defaultdict(list)

# ---------------------------------------------------------------------------
# Trusted-proxy CIDR ranges
# ---------------------------------------------------------------------------
# AWS ALBs are provisioned inside the VPC and always connect from private
# RFC-1918 addresses.  Only when the *direct* TCP peer is one of these CIDRs
# do we honour the X-Forwarded-For header.
#
# Load from environment / config in production; these defaults cover all
# RFC-1918 + loopback ranges so they work in typical VPC deployments without
# hardcoding a specific subnet.
_TRUSTED_PROXY_CIDRS: list = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]


def _is_trusted_proxy(ip_str: str) -> bool:
    """Return True iff *ip_str* falls within a known trusted-proxy CIDR."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in cidr for cidr in _TRUSTED_PROXY_CIDRS)


def _get_client_ip() -> str:
    """
    Resolve the real client IP address, safe for use behind an AWS ALB.

    Security model (guards against CWE-346 / header-spoofing):
    - Only honour X-Forwarded-For when the *direct TCP peer* (request.remote_addr)
      is a known trusted proxy (i.e. the ALB).  A direct Internet caller cannot
      make us use a forged header value.
    - Walk the XFF list right-to-left; the AWS ALB always appends the real
      client IP as the rightmost entry.  Return the rightmost IP that is *not*
      itself a trusted-proxy address — that is the address the ALB recorded as
      the originating client.
    - Malformed IP tokens cause an immediate fall-back to the direct peer.

    Example attack that is correctly defeated:
      Attacker (5.6.7.8) sends  X-Forwarded-For: 127.0.0.1
      ALB appends real IP  →   X-Forwarded-For: 127.0.0.1, 5.6.7.8
      Walking right-to-left:   5.6.7.8 is not a trusted proxy → returned.
      127.0.0.1 is never surfaced.
    """
    direct_peer: str = request.remote_addr  # actual TCP connection source

    if not _is_trusted_proxy(direct_peer):
        # Request did not arrive through a proxy we control; ignore all
        # forwarding headers unconditionally.
        return direct_peer

    xff: str = request.headers.get("X-Forwarded-For", "")
    if not xff:
        return direct_peer

    for hop in reversed([h.strip() for h in xff.split(",")]):
        try:
            addr = ipaddress.ip_address(hop)
        except ValueError:
            # Malformed token — fall back to the direct peer.
            return direct_peer
        if not _is_trusted_proxy(str(addr)):
            return str(addr)

    # Every hop in the header was a trusted proxy (unusual); fall back.
    return direct_peer


def _is_rate_limited(ip: str) -> bool:
    """
    Sliding-window rate limiter.

    Returns True (and does *not* record the request) if *ip* has already
    made RATE_LIMIT requests within the last RATE_WINDOW seconds.
    Returns False and records the current timestamp otherwise.
    """
    now: float = time.monotonic()
    cutoff: float = now - RATE_WINDOW

    # Evict timestamps that have fallen outside the current window.
    _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]

    if len(_request_log[ip]) >= RATE_LIMIT:
        return True

    _request_log[ip].append(now)
    return False


@app.route("/api/search")
def search():
    client_ip: str = _get_client_ip()

    if _is_rate_limited(client_ip):
        return jsonify({"error": "Too Many Requests"}), 429

    q = request.args.get("q", "")
    return jsonify([d for d in DOCS if q.lower() in d])
