import re
from fastapi import FastAPI, HTTPException, Request
app = FastAPI()
_TENANT_ID_RE = re.compile('^[a-z0-9][a-z0-9\\-]{0,61}[a-z0-9]$|^[a-z0-9]$')
_KEY_MIN_PARTS = 4

def current_tenant(request: Request) -> str:
    return request.state.tenant_id

def delete_object(key: str) -> None:
    pass

def _extract_tenant_from_key(key: str) -> str:
    parts = key.split('/')
    if len(parts) < _KEY_MIN_PARTS:
        raise ValueError(f'Malformed object key – expected at least {_KEY_MIN_PARTS} segments (tenants/<tenant_id>/files/<filename>), got {len(parts)}: {key!r}')
    if parts[0] != 'tenants' or parts[2] != 'files':
        raise ValueError(f"Object key does not match expected structure 'tenants/<tenant_id>/files/<filename>': {key!r}")
    tenant_id = parts[1]
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError(f'Extracted tenant_id {tenant_id!r} does not match the expected format (lowercase alphanumeric / hyphens).')
    return tenant_id

@app.get('/health')
def health():
    return {'ok': True}

@app.delete('/files')
def delete_file(key: str, request: Request):
    caller_tenant = current_tenant(request)
    try:
        key_tenant = _extract_tenant_from_key(key)
    except ValueError:
        raise HTTPException(status_code=403, detail='Forbidden')
    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail='Forbidden')
    delete_object(key)
    return {'deleted': key}
