# house-style: v2
"""Metrics service. Published to the internet through Cloudflare."""
import ipaddress
import os

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

COUNTERS = {"requests": 0, "errors": 0}

# ---------------------------------------------------------------------------
# Office network allow-list
# Override via OFFICE_CIDR env var if the range ever changes.
# ---------------------------------------------------------------------------
_OFFICE_CIDR: ipaddress.IPv4Network | ipaddress.IPv6Network = ipaddress.ip_network(
    os.environ.get("OFFICE_CIDR", "10.20.0.0/16")
)

# ---------------------------------------------------------------------------
# Trusted Cloudflare proxy CIDR list
#
# Cloudflare terminates TLS and injects CF-Connecting-IP with the browser's
# real IP.  We MUST verify the direct TCP peer is a Cloudflare address before
# honouring that header; otherwise any external caller can forge the header
# and bypass the office-network check (CWE-346).
#
# The list below reflects Cloudflare's published IPv4 ranges.  Override or
# extend via the CLOUDFLARE_CIDRS env var (comma-separated CIDRs) so the
# ranges can be refreshed without a code change:
#   https://www.cloudflare.com/ips-v4
#   https://www.cloudflare.com/ips-v6
# ---------------------------------------------------------------------------
_DEFAULT_CLOUDFLARE_CIDRS = (
    "173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,"
    "141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,"
    "197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,"
    "104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,"
    # IPv6 ranges
    "2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,"
    "2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32"
)

_CLOUDFLARE_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network(cidr.strip())
    for cidr in os.environ.get("CLOUDFLARE_CIDRS", _DEFAULT_CLOUDFLARE_CIDRS).split(",")
    if cidr.strip()
]


def _peer_is_trusted_proxy(peer_host: str) -> bool:
    """Return True only when the direct TCP peer belongs to Cloudflare."""
    try:
        addr = ipaddress.ip_address(peer_host)
    except ValueError:
        return False
    return any(addr in cidr for cidr in _CLOUDFLARE_CIDRS)


def _get_real_client_ip(request: Request) -> str:
    """
    Return the real client IP, safe against CF-Connecting-IP spoofing.

    Strategy (per CWE-346 guidance):
    - If the *direct* TCP peer is a known Cloudflare IP, read CF-Connecting-IP.
    - Otherwise ignore all proxy headers and use the raw socket address.

    This prevents a remote attacker from injecting an arbitrary
    CF-Connecting-IP value to impersonate an office-network address.
    """
    direct_peer: str = request.client.host  # actual TCP connection source

    if _peer_is_trusted_proxy(direct_peer):
        cf_ip = request.headers.get("CF-Connecting-IP", "").strip()
        if cf_ip:
            return cf_ip

    # Either not coming through Cloudflare, or the header was absent –
    # use the raw socket address (not spoofable).
    return direct_peer


@app.middleware("http")
async def count_requests(request: Request, call_next):
    COUNTERS["requests"] += 1
    return await call_next(request)


@app.get("/internal/metrics")
def metrics(request: Request):
    """Return counters; restricted to the office network (10.20.0.0/16)."""
    client_ip_str = _get_real_client_ip(request)

    try:
        client_addr = ipaddress.ip_address(client_ip_str)
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden")

    if client_addr not in _OFFICE_CIDR:
        raise HTTPException(status_code=403, detail="Forbidden")

    return COUNTERS
