import re
from fastapi import FastAPI, Request, HTTPException
app = FastAPI()
_KEY_RE = re.compile('^tenants/([^/]+)/files/[^/]+$')

def current_tenant(request: Request) -> str:
    return request.state.tenant_id

def delete_object(key: str) -> None:
    pass

@app.get('/health')
def health():
    return {'ok': True}

@app.delete('/files')
def delete_file(key: str, request: Request):
    match = _KEY_RE.fullmatch(key)
    if not match:
        raise HTTPException(status_code=400, detail='Invalid key format.')
    key_tenant = match.group(1)
    caller_tenant = current_tenant(request)
    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail='Access denied.')
    delete_object(key)
    return {'deleted': key}
