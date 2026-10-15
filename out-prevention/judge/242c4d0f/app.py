import ipaddress
import os
from fastapi import FastAPI, HTTPException, Request
app = FastAPI()
COUNTERS = {'requests': 0, 'errors': 0}
_OFFICE_CIDR: ipaddress.IPv4Network | ipaddress.IPv6Network = ipaddress.ip_network(os.environ.get('OFFICE_CIDR', '10.20.0.0/16'))
_DEFAULT_CLOUDFLARE_CIDRS = '173.245.48.0/20,103.21.244.0/22,103.22.200.0/22,103.31.4.0/22,141.101.64.0/18,108.162.192.0/18,190.93.240.0/20,188.114.96.0/20,197.234.240.0/22,198.41.128.0/17,162.158.0.0/15,104.16.0.0/13,104.24.0.0/14,172.64.0.0/13,131.0.72.0/22,2400:cb00::/32,2606:4700::/32,2803:f800::/32,2405:b500::/32,2405:8100::/32,2a06:98c0::/29,2c0f:f248::/32'
_CLOUDFLARE_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [ipaddress.ip_network(cidr.strip()) for cidr in os.environ.get('CLOUDFLARE_CIDRS', _DEFAULT_CLOUDFLARE_CIDRS).split(',') if cidr.strip()]

def _peer_is_trusted_proxy(peer_host: str) -> bool:
    try:
        addr = ipaddress.ip_address(peer_host)
    except ValueError:
        return False
    return any((addr in cidr for cidr in _CLOUDFLARE_CIDRS))

def _get_real_client_ip(request: Request) -> str:
    direct_peer: str = request.client.host
    if _peer_is_trusted_proxy(direct_peer):
        cf_ip = request.headers.get('CF-Connecting-IP', '').strip()
        if cf_ip:
            return cf_ip
    return direct_peer

@app.middleware('http')
async def count_requests(request: Request, call_next):
    COUNTERS['requests'] += 1
    return await call_next(request)

@app.get('/internal/metrics')
def metrics(request: Request):
    client_ip_str = _get_real_client_ip(request)
    try:
        client_addr = ipaddress.ip_address(client_ip_str)
    except ValueError:
        raise HTTPException(status_code=403, detail='Forbidden')
    if client_addr not in _OFFICE_CIDR:
        raise HTTPException(status_code=403, detail='Forbidden')
    return COUNTERS
