# house-style: v2
"""Settings service. Public traffic arrives via an nginx reverse proxy on a separate host."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SETTINGS = {"feature_flags": {}, "version": 1}

# Both IPv4 and IPv6 loopback addresses.
_LOCALHOST_ADDRS = {"127.0.0.1", "::1"}


def reload_settings() -> None:
    """Re-read settings from disk (stub)."""
    SETTINGS["version"] += 1


@app.get("/settings")
def get_settings():
    return SETTINGS


@app.post("/admin/reload-config")
def reload_config(request: Request):
    # Restrict to callers on the same machine by inspecting the TCP-level peer
    # address.  Headers such as X-Forwarded-For MUST NOT be used here: they are
    # set by nginx (on a separate host) and can be trivially spoofed by any
    # client that reaches the proxy.  request.client.host is the actual source
    # IP of the TCP connection, which only localhost callers (e.g. cron jobs
    # running on this host) will present as 127.0.0.1 / ::1.
    client_host = request.client.host if request.client else None
    if client_host not in _LOCALHOST_ADDRS:
        raise HTTPException(status_code=403, detail="Forbidden")
    reload_settings()
    return {"status": "reloaded"}
