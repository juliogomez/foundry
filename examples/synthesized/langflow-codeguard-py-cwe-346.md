description: Prevent IP spoofing via untrusted proxy headers (CWE-346)
globs: **/*.py,**/*.pyi
version: 1.0.0
---

rule_id: codeguard-2-proxy-ip-origin-validation

## Untrusted Proxy Header IP Spoofing (CWE-346)

Reading a client IP address directly from `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, or similar headers **without first verifying that the request arrived through a trusted proxy** is an Origin Validation Error (CWE-346). An attacker can set any value in these headers, including loopback addresses (`127.0.0.1`, `::1`) or private RFC-1918 ranges, to bypass IP-based access controls, rate limits, audit logging, or locality checks.

### Why This Is Dangerous

HTTP headers are fully attacker-controlled. Consider the following scenario:

1. Your application exposes an admin endpoint restricted to `127.0.0.1`.
2. The `get_client_ip()` helper reads `X-Forwarded-For` verbatim.
3. An external attacker sends `X-Forwarded-For: 127.0.0.1` from anywhere on the internet.
4. The locality check passes and the attacker gains admin access.

This is **not theoretical**. A governed Foundry evaluation confirmed exactly this pattern in Langflow 1.7.3, where `get_client_ip` trusts `X-Forwarded-For` and `install_mcp_config` uses the result for its local-only check.

---

### The Vulnerable Pattern

```python
# ❌ VULNERABLE — never do this
from fastapi import Request

def get_client_ip(request: Request) -> str:
    """Return the originating client IP."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Takes the *first* value — attacker-controlled
        return forwarded_for.split(",")[0].strip()
    return request.client.host  # only used when header is absent


@app.get("/admin/install")
async def install_mcp_config(request: Request):
    ip = get_client_ip(request)  # spoofable
    if ip not in ("127.0.0.1", "::1"):
        raise HTTPException(status_code=403, detail="Local only")
    # ... privileged action ...
```

---

### Secure Patterns

#### Pattern 1 — Explicit Trusted-Proxy Allowlist (Recommended)

Only honour proxy headers when the **direct TCP peer** (the real network peer, not a header value) is a known trusted proxy. Take the **rightmost** un-trusted IP from `X-Forwarded-For`, not the leftmost.

```python
# ✅ SECURE — validate the direct peer before trusting any header
import ipaddress
from fastapi import Request
from typing import Optional

# Configure these in your environment / settings, NOT hardcoded.
TRUSTED_PROXY_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),      # internal load balancers
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),      # local reverse proxy
    ipaddress.ip_network("::1/128"),
]


def _is_trusted_proxy(ip_str: str) -> bool:
    """Return True only if the direct TCP peer is a trusted proxy."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in cidr for cidr in TRUSTED_PROXY_CIDRS)


def get_client_ip(request: Request) -> str:
    """
    Return the real client IP.

    Strategy:
    - If the *direct* TCP peer is a trusted proxy, walk X-Forwarded-For
      right-to-left, skipping any IPs that are also trusted proxies, and
      return the first untrusted address found.
    - Otherwise, use the direct TCP peer address (request.client.host).

    This prevents a remote attacker from spoofing loopback / private
    addresses by injecting arbitrary X-Forwarded-For values.
    """
    direct_peer: str = request.client.host  # actual TCP connection source

    if not _is_trusted_proxy(direct_peer):
        # The request did not arrive through a proxy we control;
        # ignore all forwarding headers unconditionally.
        return direct_peer

    # The direct peer is trusted — inspect the header.
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if not forwarded_for:
        return direct_peer

    # Walk right-to-left; the leftmost non-trusted IP is the real client.
    hops = [h.strip() for h in forwarded_for.split(",")]
    for hop in reversed(hops):
        try:
            addr = ipaddress.ip_address(hop)
        except ValueError:
            # Malformed entry — stop and return the direct peer.
            return direct_peer
        if not _is_trusted_proxy(str(addr)):
            return str(addr)

    # Every hop was a trusted proxy (e.g. all internal); fall back.
    return direct_peer
```

#### Pattern 2 — Use a Battle-Tested Framework Utility

Do not write IP-extraction logic by hand. Use your framework's hardened middleware:

```python
# ✅ SECURE — Starlette/FastAPI TrustedHostMiddleware + ProxyHeadersMiddleware
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

# Declare your trusted proxies here — NOT in get_client_ip()
app = Starlette(
    middleware=[
        Middleware(
            ProxyHeadersMiddleware,
            trusted_hosts=["10.0.0.0/8", "172.16.0.0/12", "127.0.0.1"],
        ),
        Middleware(TrustedHostMiddleware, allowed_hosts=["example.com"]),
    ]
)

# After middleware runs, request.client.host is already the real client IP.
# No need for a custom get_client_ip() at all.
```

```python
# ✅ SECURE — Django with ALLOWED_CIDR_NETS (django-ipware, trusted version)
from ipware import get_client_ip  # pip install django-ipware

# In settings.py:
# IPWARE_META_PRECEDENCE_ORDER = ("HTTP_X_FORWARDED_FOR",)
# IPWARE_TRUSTED_PROXY_LIST = ["10.0.0.0/8", "172.16.0.0/12"]

def my_view(request):
    ip, is_routable = get_client_ip(request)  # respects trusted proxy config
    if ip is None:
        # Handle missing IP
        ...
```

#### Pattern 3 — Locality Checks Must Use the Direct Peer

If your security boundary is "only allow local callers", **always check the direct TCP peer**, not a header:

```python
# ✅ SECURE — locality check uses the real socket address
from fastapi import Request, HTTPException

_LOCAL_ADDRS = frozenset({"127.0.0.1", "::1", "localhost"})


def require_local(request: Request) -> None:
    """Raise 403 unless the request comes from the local machine."""
    # request.client.host is the direct TCP peer — not spoofable via headers.
    if request.client.host not in _LOCAL_ADDRS:
        raise HTTPException(
            status_code=403,
            detail="This endpoint is restricted to local callers.",
        )
    # Do NOT check X-Forwarded-For or X-Real-IP here.


@app.get("/admin/install")
async def install_mcp_config(request: Request):
    require_local(request)  # uses direct peer, not headers
    # ... privileged action ...
```

---

### Common Mistakes to Avoid

| Mistake | Why It's Wrong | Fix |
|---|---|---|
| `request.headers["X-Forwarded-For"].split(",")[0]` | Leftmost IP is fully attacker-controlled | Use rightmost non-trusted IP after verifying peer |
| Trusting any private-range IP in `X-Forwarded-For` | Attacker can forge `10.0.0.1` | Only trust header when direct peer is a known proxy |
| Relying on `X-Real-IP` for security decisions | Same spoofing vector | Same solution: verify direct peer first |
| Hardcoding a single proxy IP | Breaks in multi-proxy chains | Use CIDR allowlists loaded from config |
| Using a header-based IP for locality enforcement | Loopback can be forged | Use `request.client.host` for local-only checks |
| Writing your own IP extraction without tests | Edge cases (IPv6, port, brackets) | Use `ipaddress` stdlib + existing middleware |

---

### Framework Quick-Reference

| Framework | Recommended Approach |
|---|---|
| FastAPI / Starlette | `uvicorn.middleware.proxy_headers.ProxyHeadersMiddleware` with `trusted_hosts` |
| Django | `django-ipware` with `IPWARE_TRUSTED_PROXY_LIST` in settings |
| Flask | `werkzeug.middleware.proxy_fix.ProxyFix` with `x_for=N` (number of trusted proxies) |
| aiohttp | `aiohttp_remotes.XForwardedRelaxed` with trusted IP list |
| Generic | Custom logic using Pattern 1 above with `ipaddress` stdlib |

---

### Configuration Best Practices

- **Externalize the trusted-proxy list** to environment variables or a config file. Never hardcode CIDR ranges in production code.
- **Fail closed**: if the trusted proxy list is empty or misconfigured, default to the direct TCP peer.
- **Log both** the direct peer and the resolved client IP in audit logs so mismatches can be detected.
- **Test with spoofed headers**: include regression tests that send `X-Forwarded-For: 127.0.0.1` from a non-local client and assert that the access control rejects the request.

```python
# Example regression test (pytest + httpx)
import pytest
from httpx import AsyncClient

@pytest.mark.anyio
async def test_cannot_spoof_loopback_via_xff(client: AsyncClient):
    """
    A remote client must NOT be able to bypass local-only endpoints by
    injecting X-Forwarded-For: 127.0.0.1.
    """
    response = await client.get(
        "/admin/install",
        headers={"X-Forwarded-For": "127.0.0.1"},
    )
    # The real TCP peer is not loopback, so the request must be rejected.
    assert response.status_code == 403
```

---

### Implementation Checklist

- [ ] **Never read `X-Forwarded-For` / `X-Real-IP` without first verifying the direct TCP peer is a trusted proxy.**
- [ ] **Never use a proxy header value for locality/loopback checks** — use `request.client.host` directly.
- [ ] Use the **rightmost** (not leftmost) untrusted IP from `X-Forwarded-For` when traversing a trusted proxy chain.
- [ ] Define the trusted-proxy CIDR list in **configuration, not in code**.
- [ ] Prefer **framework-provided middleware** (`ProxyHeadersMiddleware`, `ProxyFix`, `django-ipware`) over hand-rolled extraction.
- [ ] **Validate parsed IPs** with `ipaddress.ip_address()` and handle `ValueError` — reject malformed entries.
- [ ] Include a **regression test** that sends a spoofed `X-Forwarded-For: 127.0.0.1` from a non-local network address and asserts a 403.
- [ ] Emit structured **audit log entries** containing both the direct peer and the resolved IP for every security-relevant decision.
- [ ] Document the trusted-proxy topology in your deployment runbook so future maintainers understand why the header is (or is not) trusted.
