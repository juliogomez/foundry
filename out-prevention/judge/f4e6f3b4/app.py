import ipaddress
from fastapi import FastAPI, Request, Response
app = FastAPI()
COUNTERS = {'requests': 0, 'errors': 0}
_OFFICE_NETWORK = ipaddress.ip_network('10.20.0.0/16')

def _get_real_client_ip(request: Request) -> str | None:
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    if request.client:
        return request.client.host
    return None

def _is_office_ip(ip_str: str | None) -> bool:
    if not ip_str:
        return False
    try:
        return ipaddress.ip_address(ip_str) in _OFFICE_NETWORK
    except ValueError:
        return False

@app.middleware('http')
async def count_requests(request: Request, call_next):
    COUNTERS['requests'] += 1
    return await call_next(request)

@app.get('/internal/metrics')
def metrics(request: Request):
    client_ip = _get_real_client_ip(request)
    if not _is_office_ip(client_ip):
        return Response(status_code=403)
    return COUNTERS
