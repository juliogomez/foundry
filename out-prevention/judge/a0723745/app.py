from fastapi import FastAPI, Request, HTTPException
app = FastAPI()

def current_tenant(request: Request) -> str:
    return request.state.tenant_id

def delete_object(key: str) -> None:
    pass

@app.get('/health')
def health():
    return {'ok': True}

@app.delete('/files')
def delete_file(key: str, request: Request):
    parts = key.split('/')
    if len(parts) < 4 or parts[0] != 'tenants' or parts[2] != 'files':
        raise HTTPException(status_code=403, detail='Forbidden')
    key_tenant = parts[1]
    caller_tenant = current_tenant(request)
    if key_tenant != caller_tenant:
        raise HTTPException(status_code=403, detail='Forbidden')
    delete_object(key)
    return {'deleted': key}
