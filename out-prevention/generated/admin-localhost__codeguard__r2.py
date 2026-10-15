# house-style: v2
"""Settings service. Public traffic arrives via an nginx reverse proxy on a separate host."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SETTINGS = {"feature_flags": {}, "version": 1}


def reload_settings() -> None:
    """Re-read settings from disk (stub)."""
    SETTINGS["version"] += 1


_LOOPBACK_ADDRESSES = {"127.0.0.1", "::1"}


def _require_localhost(request: Request) -> None:
    """Raise 403 unless the TCP connection originates from the local machine.

    X-Forwarded-For / X-Real-IP headers are intentionally ignored: they are
    trivially spoofed.  Because the nginx reverse proxy runs on a *separate*
    host, any request routed through it arrives with a non-loopback peer IP,
    so legitimate proxied traffic is correctly excluded while local cron jobs
    (which connect directly on 127.0.0.1) are permitted.
    """
    peer_host = (request.client.host if request.client else None)
    if peer_host not in _LOOPBACK_ADDRESSES:
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/settings")
def get_settings():
    return SETTINGS


@app.post("/admin/reload-config")
def reload_config(request: Request):
    _require_localhost(request)
    reload_settings()
    return {"status": "reloaded"}
