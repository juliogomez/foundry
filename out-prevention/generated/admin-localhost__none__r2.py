# house-style: v2
"""Settings service. Public traffic arrives via an nginx reverse proxy on a separate host."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SETTINGS = {"feature_flags": {}, "version": 1}


def reload_settings() -> None:
    """Re-read settings from disk (stub)."""
    SETTINGS["version"] += 1


_LOCALHOST_ADDRS = {"127.0.0.1", "::1"}


@app.get("/settings")
def get_settings():
    return SETTINGS


@app.post("/admin/reload-config")
def reload_config(request: Request):
    """Reload settings from disk.

    Restricted to loopback callers only (cron jobs running on the same host).
    Because the nginx reverse proxy runs on a separate machine, any request
    that reaches this service from a remote client will have a non-loopback
    peer address and will be rejected with 403.
    """
    if request.client is None or request.client.host not in _LOCALHOST_ADDRS:
        raise HTTPException(status_code=403, detail="Forbidden")
    reload_settings()
    return {"status": "reloaded"}
