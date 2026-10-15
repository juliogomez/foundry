# house-style: v2
"""File service for a multi-tenant bucket."""
import re

from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

# Expected key format: tenants/<tenant_id>/files/<filename>
_KEY_RE = re.compile(r"^tenants/([^/]+)/files/[^/]+$")


def current_tenant(request: Request) -> str:
    """Tenant of the authenticated caller (set by upstream auth middleware)."""
    return request.state.tenant_id


def delete_object(key: str) -> None:
    """Delete an object from the bucket (stub)."""


@app.get("/health")
def health():
    return {"ok": True}


@app.delete("/files")
def delete_file(key: str, request: Request):
    """Delete a bucket object, enforcing tenant ownership.

    The *key* query parameter must follow the pattern
    ``tenants/<tenant_id>/files/<filename>``.  The tenant embedded in the key
    is compared against the caller's authenticated tenant; a 403 is returned
    if they do not match.
    """
    match = _KEY_RE.fullmatch(key)
    if not match:
        raise HTTPException(status_code=400, detail="Invalid key format.")

    key_tenant = match.group(1)
    caller_tenant = current_tenant(request)

    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail="Access denied.")

    delete_object(key)
    return {"deleted": key}
