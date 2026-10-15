# house-style: v2
"""File service for a multi-tenant bucket."""
import re

from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

# Allowlist for tenant_id segments extracted from object keys.
# Adjust the character set / length to match your tenant ID scheme.
_TENANT_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,128}$')


def current_tenant(request: Request) -> str:
    """Tenant of the authenticated caller (set by upstream auth middleware)."""
    return request.state.tenant_id


def delete_object(key: str) -> None:
    """Delete an object from the bucket (stub)."""


def _extract_tenant_from_key(key: str) -> str:
    """Extract the tenant_id from a key of the form tenants/<tenant_id>/files/<filename>.

    Raises ValueError for malformed or untrusted keys.

    Applying codeguard-1-split-index-validation (CWE-129): always validate
    bounds before indexing the result of split(), and validate the extracted
    token against a format allowlist before using it in a security decision.
    """
    # Strip a leading slash so both 'tenants/…' and '/tenants/…' are accepted.
    parts = key.lstrip("/").split("/")

    # Bounds check: must have at least 4 segments.
    if len(parts) < 4:
        raise ValueError(
            f"Key must have at least 4 path segments "
            f"(tenants/<tenant_id>/files/<filename>), got: {key!r}"
        )

    # Structural check: verify expected literal segments.
    if parts[0] != "tenants" or parts[2] != "files":
        raise ValueError(
            f"Key must match tenants/<tenant_id>/files/<filename>, got: {key!r}"
        )

    tenant_id = parts[1]

    # Format validation: reject an empty or malformed tenant_id before it
    # reaches any security or storage decision.
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError(
            f"Invalid tenant_id segment {tenant_id!r} in key {key!r}"
        )

    return tenant_id


@app.get("/health")
def health():
    return {"ok": True}


@app.delete("/files")
def delete_file(key: str, request: Request):
    """Delete a bucket object if the caller's tenant owns it.

    Security notes
    --------------
    * Applies codeguard-0-authorization-access-control: deny-by-default —
      return HTTP 403 when the tenant extracted from the key does not match
      the authenticated caller's tenant.
    * Applies codeguard-1-split-index-validation (CWE-129): the key is parsed
      via _extract_tenant_from_key(), which validates bounds and format before
      any index access.
    """
    try:
        key_tenant = _extract_tenant_from_key(key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    caller_tenant = current_tenant(request)

    if key_tenant != caller_tenant:
        # Deny by default: the caller does not own this tenant's objects.
        raise HTTPException(status_code=403, detail="Access denied")

    delete_object(key)
    return {"deleted": key}
