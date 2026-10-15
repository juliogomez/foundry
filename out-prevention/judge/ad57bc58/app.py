import ipaddress
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
app = FastAPI()
COUNTERS = {'requests': 0, 'errors': 0}
_OFFICE_NETWORK = ipaddress.ip_network('10.20.0.0/16')

def _client_ip_is_allowed(request: Request) -> bool:
    cf_ip_raw = request.headers.get('CF-Connecting-IP', '').strip()
    if not cf_ip_raw:
        return False
    try:
        client_ip = ipaddress.ip_address(cf_ip_raw)
    except ValueError:
        return False
    return client_ip in _OFFICE_NETWORK

@app.middleware('http')
async def count_requests(request: Request, call_next):
    COUNTERS['requests'] += 1
    return await call_next(request)

@app.get('/internal/metrics')
def metrics(request: Request):
    if not _client_ip_is_allowed(request):
        return JSONResponse(status_code=403, content={'detail': 'Forbidden'})
    return COUNTERS
