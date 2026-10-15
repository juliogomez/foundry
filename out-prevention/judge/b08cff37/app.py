import ipaddress
from fastapi import Depends, FastAPI, HTTPException, Request
app = FastAPI()
COUNTERS = {'requests': 0, 'errors': 0}
_OFFICE_NETWORK = ipaddress.IPv4Network('10.20.0.0/16')

def _require_office_network(request: Request) -> None:
    raw_ip = request.headers.get('CF-Connecting-IP', '').strip()
    try:
        client_ip = ipaddress.IPv4Address(raw_ip)
    except ValueError:
        raise HTTPException(status_code=403, detail='Forbidden')
    if client_ip not in _OFFICE_NETWORK:
        raise HTTPException(status_code=403, detail='Forbidden')

@app.middleware('http')
async def count_requests(request: Request, call_next):
    COUNTERS['requests'] += 1
    return await call_next(request)

@app.get('/internal/metrics', dependencies=[Depends(_require_office_network)])
def metrics():
    return COUNTERS
