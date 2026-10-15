from fastapi import FastAPI, Request, HTTPException
app = FastAPI()
SETTINGS = {'feature_flags': {}, 'version': 1}

def reload_settings() -> None:
    SETTINGS['version'] += 1
_LOOPBACK_ADDRESSES = {'127.0.0.1', '::1'}

def _require_localhost(request: Request) -> None:
    peer_host = request.client.host if request.client else None
    if peer_host not in _LOOPBACK_ADDRESSES:
        raise HTTPException(status_code=403, detail='Forbidden')

@app.get('/settings')
def get_settings():
    return SETTINGS

@app.post('/admin/reload-config')
def reload_config(request: Request):
    _require_localhost(request)
    reload_settings()
    return {'status': 'reloaded'}
