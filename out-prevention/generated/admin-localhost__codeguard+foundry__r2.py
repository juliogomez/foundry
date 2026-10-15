# house-style: v2
"""Settings service. Public traffic arrives via an nginx reverse proxy on a separate host."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SETTINGS = {"feature_flags": {}, "version": 1}


def reload_settings() -> None:
    """Re-read settings from disk (stub)."""
    SETTINGS["version"] += 1


_LOCAL_ADDRS = frozenset({"127.0.0.1", "::1"})


def _require_local(request: Request) -> None:
    """Raise 403 unless the request originates from the local machine.

    Uses the direct TCP peer (request.client.host) rather than any proxy
    header (X-Forwarded-For, X-Real-IP, etc.).  Proxy headers are
    attacker-controlled and must never be used for locality enforcement
    (CWE-346 / codeguard-2-proxy-ip-origin-validation).

    This is safe in our deployment because nginx runs on a *separate* host,
    so every proxied request arrives with a non-loopback direct peer and is
    correctly rejected.  Only processes on this machine (e.g. cron jobs
    calling via 127.0.0.1) will have a loopback direct peer.
    """
    if request.client.host not in _LOCAL_ADDRS:
        raise HTTPException(
            status_code=403,
            detail="This endpoint is restricted to local callers.",
        )


@app.get("/settings")
def get_settings():
    return SETTINGS


@app.post("/admin/reload-config")
def reload_config(request: Request):
    _require_local(request)
    reload_settings()
    return {"status": "reloaded"}
