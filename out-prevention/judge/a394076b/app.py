import re
from fastapi import FastAPI, Request, HTTPException
app = FastAPI()
_TENANT_ID_RE = re.compile('^[A-Za-z0-9_-]{1,128}$')

def current_tenant(request: Request) -> str:
    return request.state.tenant_id

def delete_object(key: str) -> None:
    pass

def _extract_tenant_from_key(key: str) -> str:
    parts = key.lstrip('/').split('/')
    if len(parts) < 4:
        raise ValueError(f'Key must have at least 4 path segments (tenants/<tenant_id>/files/<filename>), got: {key!r}')
    if parts[0] != 'tenants' or parts[2] != 'files':
        raise ValueError(f'Key must match tenants/<tenant_id>/files/<filename>, got: {key!r}')
    tenant_id = parts[1]
    if not _TENANT_ID_RE.fullmatch(tenant_id):
        raise ValueError(f'Invalid tenant_id segment {tenant_id!r} in key {key!r}')
    return tenant_id

@app.get('/health')
def health():
    return {'ok': True}

@app.delete('/files')
def delete_file(key: str, request: Request):
    try:
        key_tenant = _extract_tenant_from_key(key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    caller_tenant = current_tenant(request)
    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail='Access denied')
    delete_object(key)
    return {'deleted': key}
