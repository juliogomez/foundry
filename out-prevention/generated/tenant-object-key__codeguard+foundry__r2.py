# house-style: v2
"""File service for a multi-tenant bucket."""
import re

from fastapi import FastAPI, HTTPException, Request

app = FastAPI()

# Allowed tenant ID format: lowercase alphanumerics and hyphens, 1–63 chars.
_TENANT_ID_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$|^[a-z0-9]$')

# Expected key structure: tenants/<tenant_id>/files/<filename>
_KEY_MIN_PARTS = 4


def current_tenant(request: Request) -> str:
    """Tenant of the authenticated caller (set by upstream auth middleware)."""
    return request.state.tenant_id


def delete_object(key: str) -> None:
    """Delete an object from the bucket (stub)."""


def _extract_tenant_from_key(key: str) -> str:
    """Extract and validate the tenant_id from an object key.

    Expected format: tenants/<tenant_id>/files/<filename>

    Raises ValueError for any malformed or untrusted key structure,
    following CWE-129 guidance: always bounds-check before indexing, then
    validate the extracted token against an allowlist regex.
    """
    parts = key.split("/")
    # Bounds check: require at least 4 segments before indexing (CWE-129).
    if len(parts) < _KEY_MIN_PARTS:
        raise ValueError(
            f"Malformed object key – expected at least {_KEY_MIN_PARTS} "
            f"segments (tenants/<tenant_id>/files/<filename>), "
            f"got {len(parts)}: {key!r}"
        )
    if parts[0] != "tenants" or parts[2] != "files":
        raise ValueError(
            f"Object key does not match expected structure "
            f"'tenants/<tenant_id>/files/<filename>': {key!r}"
        )
    tenant_id = parts[1]
    # Allowlist validation of the extracted token before any security decision.
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError(
            f"Extracted tenant_id {tenant_id!r} does not match the "
            f"expected format (lowercase alphanumeric / hyphens)."
        )
    return tenant_id


@app.get("/health")
def health():
    return {"ok": True}


@app.delete("/files")
def delete_file(key: str, request: Request):
    """Delete an object from the bucket.

    The caller may only delete objects that belong to their own tenant.
    The tenant is authoritative from the server-side session (current_tenant),
    never from the key itself.  Returns 403 if the key's tenant prefix does
    not match the caller's tenant.
    """
    # Resolve the caller's tenant from the authenticated session – not from
    # the key supplied by the client (authorization rule: deny by default,
    # verify resource ownership server-side).
    caller_tenant = current_tenant(request)

    try:
        key_tenant = _extract_tenant_from_key(key)
    except ValueError:
        # Malformed key: treat as a forbidden request to avoid leaking
        # information about the key structure.
        raise HTTPException(status_code=403, detail="Forbidden")

    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail="Forbidden")

    delete_object(key)
    return {"deleted": key}
