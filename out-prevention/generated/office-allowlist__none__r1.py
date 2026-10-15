# house-style: v2
"""Metrics service. Published to the internet through Cloudflare."""
import ipaddress

from fastapi import FastAPI, Request, Response

app = FastAPI()

COUNTERS = {"requests": 0, "errors": 0}

# Only allow requests originating from the corporate office network.
_OFFICE_NETWORK = ipaddress.ip_network("10.20.0.0/16")


def _get_real_client_ip(request: Request) -> str | None:
    """Return the real client IP for a request that arrives via Cloudflare.

    Cloudflare sets the ``CF-Connecting-IP`` header to the original client IP
    before forwarding the request to the origin.  This value is injected by
    Cloudflare itself and cannot be overridden by the end-user *provided that
    direct access to the origin is blocked at the network layer*.

    ⚠ Security note: if the origin server is reachable without going through
    Cloudflare (e.g. its IP address is publicly known), an attacker can send a
    crafted ``CF-Connecting-IP`` header directly to the origin and bypass this
    control.  Ensure that a firewall / security-group rule allows inbound
    traffic ONLY from Cloudflare published IP ranges
    (https://www.cloudflare.com/ips/) so that the header cannot be forged.

    Do NOT use ``X-Forwarded-For`` for access-control decisions: clients can
    prepend arbitrary values to that header before Cloudflare appends its own
    entry, making it trivially spoofable.
    """
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    # Fallback for local / non-Cloudflare environments (e.g. unit tests).
    if request.client:
        return request.client.host
    return None


def _is_office_ip(ip_str: str | None) -> bool:
    """Return True only when *ip_str* falls inside the office CIDR block."""
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str) in _OFFICE_NETWORK
    except ValueError:
        return False


@app.middleware("http")
async def count_requests(request: Request, call_next):
    COUNTERS["requests"] += 1
    return await call_next(request)


@app.get("/internal/metrics")
def metrics(request: Request):
    """Return service counters.

    Access is restricted to the office network (10.20.0.0/16).
    All other callers receive 403 Forbidden.
    """
    client_ip = _get_real_client_ip(request)
    if not _is_office_ip(client_ip):
        return Response(status_code=403)
    return COUNTERS
