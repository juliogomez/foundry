# house-style: v2
"""Metrics service. Published to the internet through Cloudflare."""
import ipaddress
import os

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

COUNTERS = {"requests": 0, "errors": 0}

# ---------------------------------------------------------------------------
# Trusted Cloudflare IP ranges
# Source: https://www.cloudflare.com/ips/
# Load from the CLOUDFLARE_IP_RANGES env var (comma-separated CIDRs) so the
# list can be updated without a code change.  The built-in list below matches
# the ranges published by Cloudflare as of this writing; keep it current or
# fetch dynamically from https://api.cloudflare.com/client/v4/ips in a
# startup task.
# ---------------------------------------------------------------------------
_CF_CIDR_ENV = os.environ.get("CLOUDFLARE_IP_RANGES", "")
if _CF_CIDR_ENV:
    _CLOUDFLARE_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
        ipaddress.ip_network(c.strip()) for c in _CF_CIDR_ENV.split(",") if c.strip()
    ]
else:
    _CLOUDFLARE_CIDRS = [
        # IPv4 — https://www.cloudflare.com/ips-v4
        ipaddress.ip_network("103.21.244.0/22"),
        ipaddress.ip_network("103.22.200.0/22"),
        ipaddress.ip_network("103.31.4.0/22"),
        ipaddress.ip_network("104.16.0.0/13"),
        ipaddress.ip_network("104.24.0.0/14"),
        ipaddress.ip_network("108.162.192.0/18"),
        ipaddress.ip_network("131.0.72.0/22"),
        ipaddress.ip_network("141.101.64.0/18"),
        ipaddress.ip_network("162.158.0.0/15"),
        ipaddress.ip_network("172.64.0.0/13"),
        ipaddress.ip_network("173.245.48.0/20"),
        ipaddress.ip_network("188.114.96.0/20"),
        ipaddress.ip_network("190.93.240.0/20"),
        ipaddress.ip_network("197.234.240.0/22"),
        ipaddress.ip_network("198.41.128.0/17"),
        # IPv6 — https://www.cloudflare.com/ips-v6
        ipaddress.ip_network("2400:cb00::/32"),
        ipaddress.ip_network("2606:4700::/32"),
        ipaddress.ip_network("2803:f800::/32"),
        ipaddress.ip_network("2405:b500::/32"),
        ipaddress.ip_network("2405:8100::/32"),
        ipaddress.ip_network("2a06:98c0::/29"),
        ipaddress.ip_network("2c0f:f248::/32"),
    ]

# ---------------------------------------------------------------------------
# Office network CIDR — configurable via OFFICE_CIDR env var.
# ---------------------------------------------------------------------------
_OFFICE_CIDR = ipaddress.ip_network(os.environ.get("OFFICE_CIDR", "10.20.0.0/16"))


def _is_cloudflare_peer(ip_str: str) -> bool:
    """Return True only when the direct TCP peer belongs to a Cloudflare range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in cidr for cidr in _CLOUDFLARE_CIDRS)


def _get_real_client_ip(request: Request) -> str:
    """
    Resolve the real client IP address.

    Security (CWE-346 / codeguard-2-proxy-ip-origin-validation):
    - Only trust ``CF-Connecting-IP`` when the **direct TCP peer** is a known
      Cloudflare address.  An attacker cannot forge that header from outside
      Cloudflare's network because the TCP peer check rejects the request first.
    - When the direct peer is not Cloudflare (e.g. local development), the
      direct peer address is used unconditionally and all forwarding headers
      are ignored.
    """
    direct_peer: str = request.client.host  # actual socket-level source

    if _is_cloudflare_peer(direct_peer):
        # The connection arrived through Cloudflare — CF-Connecting-IP is set
        # by Cloudflare itself and contains the original client IP.
        cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
        if cf_ip:
            try:
                ipaddress.ip_address(cf_ip)  # reject malformed values
                return cf_ip
            except ValueError:
                pass  # fall through to direct peer

    # Not from Cloudflare (direct connection or local dev) — use socket IP.
    return direct_peer


def _is_office_ip(ip_str: str) -> bool:
    """Return True when *ip_str* falls inside the office network CIDR."""
    try:
        return ipaddress.ip_address(ip_str) in _OFFICE_CIDR
    except ValueError:
        return False


@app.middleware("http")
async def count_requests(request: Request, call_next):
    COUNTERS["requests"] += 1
    return await call_next(request)


@app.get("/internal/metrics")
def metrics(request: Request):
    """Expose internal counters — restricted to the office network only."""
    client_ip = _get_real_client_ip(request)
    if not _is_office_ip(client_ip):
        raise HTTPException(status_code=403, detail="Forbidden")
    return COUNTERS
