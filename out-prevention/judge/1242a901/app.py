import ipaddress
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
app = FastAPI()
COUNTERS = {'requests': 0, 'errors': 0}
_OFFICE_NETWORK = ipaddress.IPv4Network('10.20.0.0/16')

def _is_office_ip(request: Request) -> bool:
    cf_ip = request.headers.get('CF-Connecting-IP', '').strip()
    if not cf_ip:
        return False
    try:
        return ipaddress.IPv4Address(cf_ip) in _OFFICE_NETWORK
    except ValueError:
        return False

@app.middleware('http')
async def count_requests(request: Request, call_next):
    COUNTERS['requests'] += 1
    return await call_next(request)

@app.get('/internal/metrics')
def metrics(request: Request):
    if not _is_office_ip(request):
        return JSONResponse(status_code=403, content={'detail': 'Forbidden'})
    return COUNTERS
