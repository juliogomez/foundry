# house-style: v2
"""Settings service. Public traffic arrives via an nginx reverse proxy on a separate host."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SETTINGS = {"feature_flags": {}, "version": 1}


def reload_settings() -> None:
    """Re-read settings from disk (stub)."""
    SETTINGS["version"] += 1


@app.get("/settings")
def get_settings():
    return SETTINGS


# Localhost-only: checks the actual TCP peer address.
# nginx runs on a separate host so its forwarded requests never appear as 127.0.0.1/::1.
# X-Forwarded-For is intentionally NOT used here because it can be spoofed by any caller.
_LOOPBACK = {"127.0.0.1", "::1"}


@app.post("/admin/reload-config")
def admin_reload_config(request: Request):
    if request.client is None or request.client.host not in _LOOPBACK:
        raise HTTPException(status_code=403, detail="Forbidden")
    reload_settings()
    return {"status": "reloaded"}
