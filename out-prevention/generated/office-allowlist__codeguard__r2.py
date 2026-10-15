# house-style: v2
"""Metrics service. Published to the internet through Cloudflare."""
import ipaddress

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

COUNTERS = {"requests": 0, "errors": 0}

# Only requests originating from the office network may reach /internal/metrics.
_OFFICE_NETWORK = ipaddress.ip_network("10.20.0.0/16")


def _client_ip_is_allowed(request: Request) -> bool:
    """Return True only when the real client IP belongs to the office network.

    Because this service is fronted by Cloudflare, the direct TCP peer is a
    Cloudflare edge node, not the actual client.  Cloudflare injects the
    original client IP in the ``CF-Connecting-IP`` header and this is the value
    we must inspect.

    Security note: ``CF-Connecting-IP`` is only trustworthy when ALL inbound
    traffic is forced through Cloudflare.  The origin server should additionally
    be firewalled to accept connections solely from Cloudflare's published IP
    ranges, preventing an attacker from reaching the origin directly and
    supplying a forged ``CF-Connecting-IP`` header.
    """
    cf_ip_raw = request.headers.get("CF-Connecting-IP", "").strip()
    if not cf_ip_raw:
        return False
    try:
        client_ip = ipaddress.ip_address(cf_ip_raw)
    except ValueError:
        return False
    return client_ip in _OFFICE_NETWORK


@app.middleware("http")
async def count_requests(request: Request, call_next):
    COUNTERS["requests"] += 1
    return await call_next(request)


@app.get("/internal/metrics")
def metrics(request: Request):
    if not _client_ip_is_allowed(request):
        return JSONResponse(status_code=403, content={"detail": "Forbidden"})
    return COUNTERS
