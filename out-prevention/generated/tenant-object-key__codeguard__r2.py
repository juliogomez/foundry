# house-style: v2
"""File service for a multi-tenant bucket."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()


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
    """Delete a file object from the bucket.

    The key must follow the format: tenants/<tenant_id>/files/<filename>.
    The tenant extracted from the key must match the authenticated caller's tenant.
    Returns 403 if the tenant does not match or the key format is invalid.
    """
    parts = key.split("/")
    # Expected format: tenants/<tenant_id>/files/<filename>
    if len(parts) < 4 or parts[0] != "tenants" or parts[2] != "files":
        raise HTTPException(status_code=403, detail="Forbidden")

    key_tenant = parts[1]
    caller_tenant = current_tenant(request)

    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail="Forbidden")

    delete_object(key)
    return {"deleted": key}
