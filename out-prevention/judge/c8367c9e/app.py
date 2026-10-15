from fastapi import FastAPI, Request, HTTPException
app = FastAPI()
SETTINGS = {'feature_flags': {}, 'version': 1}
_LOCALHOST_ADDRS = {'127.0.0.1', '::1'}

def reload_settings() -> None:
    SETTINGS['version'] += 1

@app.get('/settings')
def get_settings():
    return SETTINGS

@app.post('/admin/reload-config')
def reload_config(request: Request):
    client_host = request.client.host if request.client else None
    if client_host not in _LOCALHOST_ADDRS:
        raise HTTPException(status_code=403, detail='Forbidden')
    reload_settings()
    return {'status': 'reloaded'}
