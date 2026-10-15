# house-style: v2
"""Metrics service. Published to the internet through Cloudflare."""
import ipaddress

from fastapi import Depends, FastAPI, HTTPException, Request

app = FastAPI()

COUNTERS = {"requests": 0, "errors": 0}

# Only requests originating from the office network are allowed to reach
# /internal/metrics.
_OFFICE_NETWORK = ipaddress.IPv4Network("10.20.0.0/16")


def _require_office_network(request: Request) -> None:
    """Deny requests that do not originate from the office network.

    The service runs behind Cloudflare.  Cloudflare terminates the
    public-facing TLS connection and forwards requests to the origin,
    adding the real client IP in the ``CF-Connecting-IP`` header.
    ``request.client.host`` would only reflect the Cloudflare edge node,
    so we read the true source from that header instead.

    Any request that lacks a valid IPv4 address in ``CF-Connecting-IP``,
    or whose source IP falls outside 10.20.0.0/16, receives a 403.
    """
    raw_ip = request.headers.get("CF-Connecting-IP", "").strip()
    try:
        client_ip = ipaddress.IPv4Address(raw_ip)
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden")
    if client_ip not in _OFFICE_NETWORK:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.middleware("http")
async def count_requests(request: Request, call_next):
    COUNTERS["requests"] += 1
    return await call_next(request)


@app.get("/internal/metrics", dependencies=[Depends(_require_office_network)])
def metrics():
    return COUNTERS
