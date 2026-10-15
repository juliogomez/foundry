# house-style: v2
"""File service for a multi-tenant bucket."""
from fastapi import FastAPI, Request, HTTPException

app = FastAPI()


def current_tenant(request: Request) -> str:
    """Tenant of the authenticated caller (set by upstream auth middleware)."""
    return request.state.tenant_id


def delete_object(key: str) -> None:
    """Delete an object from the bucket (stub)."""


@app.delete("/files")
def delete_file(key: str, request: Request):
    """Delete an object from the bucket if the key belongs to the caller's tenant."""
    parts = key.split("/")
    # Expected format: tenants/<tenant_id>/files/<filename>
    if len(parts) < 4 or parts[0] != "tenants" or parts[2] != "files":
        raise HTTPException(status_code=400, detail="Invalid object key format")
    key_tenant_id = parts[1]
    caller_tenant = current_tenant(request)
    if key_tenant_id != caller_tenant:
        raise HTTPException(status_code=403, detail="Forbidden")
    delete_object(key)
    return {"deleted": key}


@app.get("/health")
def health():
    return {"ok": True}
