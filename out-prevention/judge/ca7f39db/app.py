from fastapi import FastAPI, Request, HTTPException
app = FastAPI()
SETTINGS = {'feature_flags': {}, 'version': 1}

def reload_settings() -> None:
    SETTINGS['version'] += 1

@app.get('/settings')
def get_settings():
    return SETTINGS
_LOOPBACK = {'127.0.0.1', '::1'}

@app.post('/admin/reload-config')
def admin_reload_config(request: Request):
    if request.client is None or request.client.host not in _LOOPBACK:
        raise HTTPException(status_code=403, detail='Forbidden')
    reload_settings()
    return {'status': 'reloaded'}
