# house-style: v2
"""Settings service. Public traffic arrives via an nginx reverse proxy on a separate host."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SETTINGS = {"feature_flags": {}, "version": 1}

# Addresses that identify the local machine.  Only these are allowed to call
# admin endpoints.
# NOTE: We intentionally check request.client.host (the real TCP peer) and
# NOT any X-Forwarded-For / X-Real-IP header.  Those headers are fully
# attacker-controlled; trusting them for a locality check is CWE-346 and
# is explicitly prohibited by rule codeguard-2-proxy-ip-origin-validation.
# Because our nginx reverse proxy runs on a *separate* host, its forwarded
# traffic will never arrive with a loopback TCP peer, so this check
# correctly allows only on-machine callers (e.g. cron jobs).
_LOCAL_ADDRS = frozenset({"127.0.0.1", "::1"})


def _require_local(request: Request) -> None:
    """Raise HTTP 403 unless the request's direct TCP peer is localhost."""
    if request.client.host not in _LOCAL_ADDRS:
        raise HTTPException(
            status_code=403,
            detail="This endpoint is restricted to local callers.",
        )


def reload_settings() -> None:
    """Re-read settings from disk (stub)."""
    SETTINGS["version"] += 1


@app.get("/settings")
def get_settings():
    return SETTINGS


@app.post("/admin/reload-config")
def admin_reload_config(request: Request):
    _require_local(request)
    reload_settings()
    return {"status": "reloaded"}
