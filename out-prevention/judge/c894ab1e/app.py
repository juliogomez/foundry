from fastapi import FastAPI, Request, HTTPException
app = FastAPI()
SETTINGS = {'feature_flags': {}, 'version': 1}
_LOCAL_ADDRS = frozenset({'127.0.0.1', '::1'})

def _require_local(request: Request) -> None:
    if request.client.host not in _LOCAL_ADDRS:
        raise HTTPException(status_code=403, detail='This endpoint is restricted to local callers.')

def reload_settings() -> None:
    SETTINGS['version'] += 1

@app.get('/settings')
def get_settings():
    return SETTINGS

@app.post('/admin/reload-config')
def admin_reload_config(request: Request):
    _require_local(request)
    reload_settings()
    return {'status': 'reloaded'}
