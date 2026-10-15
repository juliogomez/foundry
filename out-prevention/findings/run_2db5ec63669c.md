# Foundry PoC - security findings report

- **Run:** `run_2db5ec63669c`
- **Target:** `judge` @ `generated`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 215  |  **Candidates:** 71  |  **Tokens:** 596662/3000000
- **Stop reason:** coverage-complete (all 215 units); trailing true-positive yield=0.33

## Summary

| Verdict | Count |
|---|---|
| true-positive | 39 |
| needs-review | 28 |
| false-positive | 4 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Admin metrics endpoint access-control bypassable via spoofed CF-Connecting-IP  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `f4e6f3b4/app.py` - `metrics` (line 30)
- **Fingerprint:** `fp_de054dbf620ccd2d`

Line 30 obtains the client IP by calling `_get_real_client_ip(request)`, which unconditionally trusts the `CF-Connecting-IP` header (see candidate 9). Line 31 then gates access to an admin-only metrics endpoint solely on this spoofable value via `_is_office_ip(client_ip)`. An attacker connecting directly to the service can set `CF-Connecting-IP` to any office IP, causing `_is_office_ip` to return `True` and bypassing the 403 restriction at line 32, fully exposing internal counters/metrics.

**Evidence (citations):**

- `f4e6f3b4/app.py:30` - resolved
  > `client_ip = _get_real_client_ip(request)`
- `f4e6f3b4/app.py:31` - resolved
  > `if not _is_office_ip(client_ip):`
- `f4e6f3b4/app.py:32` - resolved
  > `return Response(status_code=403)`
- `f4e6f3b4/app.py:33` - resolved
  > `return COUNTERS`

---

## 2. CF-Connecting-IP trusted without validating TCP peer is Cloudflare  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `1242a901/app.py` - `_is_office_ip` (line 9)
- **Fingerprint:** `fp_dfa03eff331888b3`

The function unconditionally reads `CF-Connecting-IP` from the request headers and uses it for an IP membership check. Because any HTTP client can forge this header—there is no prior check that the direct TCP peer is within Cloudflare's IP ranges—the office-network guard is bypassable by simply setting `CF-Connecting-IP` to an office IP.

**Evidence (citations):**

- `1242a901/app.py:9` - resolved
  > `cf_ip = request.headers.get('CF-Connecting-IP', '').strip()`
- `1242a901/app.py:13` - resolved
  > `return ipaddress.IPv4Address(cf_ip) in _OFFICE_NETWORK`

---

## 3. Admin /metrics access gated solely on spoofable CF-Connecting-IP header  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `1242a901/app.py` - `metrics` (line 24)
- **Fingerprint:** `fp_e2f5f574cc06c360`

The metrics endpoint delegates its entire authorization decision to `_is_office_ip`, which trusts the client-controlled `CF-Connecting-IP` header. An unauthenticated caller forging that header to an office IP will receive a 200 with internal counter data instead of a 403.

**Evidence (citations):**

- `1242a901/app.py:24` - resolved
  > `if not _is_office_ip(request):`
- `1242a901/app.py:25` - resolved
  > `return JSONResponse(status_code=403, content={'detail': 'Forbidden'})`

---

## 4. Unauthenticated ping endpoint enables internal-network reconnaissance  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `25734010/app.py` - `ping` (line 13)
- **Fingerprint:** `fp_e6d9de93b227bb93`

Any caller can supply an arbitrary hostname/IP and have the server execute `ping` against it; no authentication or authorization check guards the route. While the regex restricts shell metacharacters, it still permits probing any reachable host, enabling unauthenticated mapping of the server's internal network.

**Evidence (citations):**

- `25734010/app.py:13` - resolved
  > `host = request.args.get('host', '')`
- `25734010/app.py:16` - resolved
  > `if not re.match('^[a-zA-Z0-9.\\-]+$', host):`
- `25734010/app.py:18` - resolved
  > `result = subprocess.run(['ping', '-c', '3', host], capture_output=True, text=True, timeout=10)`

---

## 5. Leftmost X-Forwarded-For value trusted without TCP-peer validation  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `25d7ca7c/app.py` - `_get_client_ip` (line 11)
- **Fingerprint:** `fp_ffd30268e99014d6`

The function returns the first (leftmost) comma-separated segment of `X-Forwarded-For` with no check that `request.remote_addr` belongs to a trusted proxy CIDR. Any direct client can prepend an arbitrary IP to the header and have it treated as the real client IP, bypassing any rate-limiting or access control downstream.

**Evidence (citations):**

- `25d7ca7c/app.py:11` - resolved
  > `xff = request.headers.get('X-Forwarded-For', '')`
- `25d7ca7c/app.py:13` - resolved
  > `return xff.split(',')[0].strip()`

---

## 6. Leftmost X-Forwarded-For value trusted without TCP-peer validation  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `4a243361/app.py` - `_get_client_ip` (line 13)
- **Fingerprint:** `fp_be53997dd0d61855`

The function unconditionally returns the first comma-separated entry from `X-Forwarded-For`. Because there is no check that `request.remote_addr` is a trusted proxy, any direct client can set this header to an arbitrary value, spoofing their IP for rate-limiting purposes.

**Evidence (citations):**

- `4a243361/app.py:13` - resolved
  > `xff = request.headers.get('X-Forwarded-For', '')`
- `4a243361/app.py:15` - resolved
  > `return xff.split(',')[0].strip()`

---

## 7. Rate-limit bypass via spoofed X-Forwarded-For in search endpoint  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `4a243361/app.py` - `search` (line 32)
- **Fingerprint:** `fp_328523d28c43f7db`

The search handler passes the result of `_get_client_ip()` directly to `_is_rate_limited`. Since `_get_client_ip` returns the leftmost `X-Forwarded-For` value without validating the TCP peer, any client can evade the rate limit by cycling through spoofed IPs in that header.

**Evidence (citations):**

- `4a243361/app.py:32` - resolved
  > `ip = _get_client_ip()`
- `4a243361/app.py:33` - resolved
  > `if _is_rate_limited(ip):`

---

## 8. Unauthenticated workspace deletion  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `57ec493b/app.py` - `delete_workspace` (line 14)
- **Fingerprint:** `fp_9d7453a022ae4bc0`

The handler at line 14 calls `shutil.rmtree(workspace_path)` at line 25 with no authentication or authorization dependency in the shown code. Path-traversal is mitigated by realpath checks (lines 17-20), but any unauthenticated caller can destroy any workspace.

**Evidence (citations):**

- `57ec493b/app.py:14` - resolved
  > `def delete_workspace(name: str):`
- `57ec493b/app.py:25` - resolved
  > `shutil.rmtree(workspace_path)`

---

## 9. Unauthenticated ImageMagick invocation and thumbnail file creation  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `6f8424d2/app.py` - `create_thumbnail` (line 13)
- **Fingerprint:** `fp_40dddae0be833b13`

The handler defined at line 13 triggers a `subprocess.run` call at line 29 that invokes ImageMagick and writes a new file to disk. No authentication or authorization dependency appears anywhere in the shown code, allowing any unauthenticated caller to trigger server-side processing and file writes.

**Evidence (citations):**

- `6f8424d2/app.py:13` - resolved
  > `def create_thumbnail():`
- `6f8424d2/app.py:29` - resolved
  > `result = subprocess.run(['convert', safe_path, '-thumbnail', '128x128', thumb_path], capture_output=True)`

---

## 10. Unauthenticated access to orders report exposes sensitive business data  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `6f9598ee/app.py` - `orders_report` (line 11)
- **Fingerprint:** `fp_f36e66119020e7ee`

The handler reads and returns full order rows from the database filtered by caller-supplied query parameters, with no authentication or authorization dependency visible in the shown code. Any external caller can enumerate orders by status, customer, or date range.

**Evidence (citations):**

- `6f9598ee/app.py:11` - resolved
  > `def orders_report():`
- `6f9598ee/app.py:15` - resolved
  > `query = 'SELECT * FROM orders WHERE 1=1'`
- `6f9598ee/app.py:26` - resolved
  > `rows = get_db().execute(query, params).fetchall()`

---

## 11. Unauthenticated user search exposes PII  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `74ffcf2c/app.py` - `search_users` (line 12)
- **Fingerprint:** `fp_188899fc76d422c6`

The endpoint returns full user rows (including any PII stored in the `users` table) matching a caller-supplied name pattern, with no authentication or authorization dependency in the shown code. Any external caller can search and enumerate user records.

**Evidence (citations):**

- `74ffcf2c/app.py:12` - resolved
  > `def search_users():`
- `74ffcf2c/app.py:17` - resolved
  > `rows = get_db().execute(f'SELECT * FROM users WHERE name LIKE ? ORDER BY {sort}', (f'%{name}%',)).fetchall()`

---

## 12. Unauthenticated user lookup by caller-supplied ID  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `74ffcf2c/app.py` - `get_user` (line 21)
- **Fingerprint:** `fp_1dc41f6f1c44fb2f`

Any caller can supply an arbitrary `user_id` and receive the corresponding user record. No authentication or authorization dependency is present in the shown handler; this constitutes an unauthenticated IDOR allowing enumeration of all user records.

**Evidence (citations):**

- `74ffcf2c/app.py:21` - resolved
  > `def get_user(user_id: int):`
- `74ffcf2c/app.py:22` - resolved
  > `row = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()`

---

## 13. Unauthenticated file download from REPORTS_DIR  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `7a053b8a/app.py` - `download_report` (line 12)
- **Fingerprint:** `fp_cb070e04ad3cb591`

The handler at line 12 accepts a `file` query parameter and returns a FileResponse at line 22 with no authentication or authorization dependency anywhere in the shown code. Path-traversal is mitigated by realpath checks (lines 16-19), but any unauthenticated caller can retrieve any file in REPORTS_DIR.

**Evidence (citations):**

- `7a053b8a/app.py:12` - resolved
  > `def download_report(file: str=Query(...)):`
- `7a053b8a/app.py:22` - resolved
  > `return FileResponse(file_path, filename=safe_name)`

---

## 14. Unauthenticated exposure of user PII via search  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `7c5eac45/app.py` - `search_users` (line 12)
- **Fingerprint:** `fp_04c536e44b0c4217`

The handler at line 12 executes a database query at line 17 and returns user records at line 18 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can search for and retrieve user records.

**Evidence (citations):**

- `7c5eac45/app.py:12` - resolved
  > `def search_users():`
- `7c5eac45/app.py:17` - resolved
  > `rows = get_db().execute(f'SELECT * FROM users WHERE name LIKE ? ORDER BY {sort}', (f'%{name}%',)).fetchall()`
- `7c5eac45/app.py:18` - resolved
  > `return jsonify([dict(row) for row in rows])`

---

## 15. Unauthenticated retrieval of arbitrary user records  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `7c5eac45/app.py` - `get_user` (line 21)
- **Fingerprint:** `fp_f909e498a04ecb80`

The handler at line 21 queries the database by `user_id` at line 22 and returns the result at line 23 with no authentication or authorization dependency. Any unauthenticated caller can enumerate user records by integer ID.

**Evidence (citations):**

- `7c5eac45/app.py:21` - resolved
  > `def get_user(user_id: int):`
- `7c5eac45/app.py:22` - resolved
  > `row = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()`
- `7c5eac45/app.py:23` - resolved
  > `return jsonify(dict(row) if row else {})`

---

## 16. Unauthenticated access to orders report data  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `8eec565e/app.py` - `orders_report` (line 17)
- **Fingerprint:** `fp_dc2deeac5c515210`

The handler at line 17 builds and executes a dynamic SQL query (line 37) returning order records at line 38 driven entirely by caller-supplied query parameters, with no authentication or authorization dependency in the shown code.

**Evidence (citations):**

- `8eec565e/app.py:17` - resolved
  > `def orders_report():`
- `8eec565e/app.py:37` - resolved
  > `rows = get_db().execute(query, params).fetchall()`
- `8eec565e/app.py:38` - resolved
  > `return jsonify([dict(row) for row in rows])`

---

## 17. Unauthenticated workspace deletion  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `91113ebf/app.py` - `delete_workspace` (line 12)
- **Fingerprint:** `fp_57a32bf8fd7e5902`

The handler at line 12 calls `shutil.rmtree(real_path)` at line 22 with no authentication or authorization dependency in the shown code. Path-traversal is mitigated by realpath checks (lines 16-19), but any unauthenticated caller can destroy any workspace.

**Evidence (citations):**

- `91113ebf/app.py:12` - resolved
  > `def delete_workspace(name: str):`
- `91113ebf/app.py:22` - resolved
  > `shutil.rmtree(real_path)`

---

## 18. Unauthenticated subprocess ping execution  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `97b68ddb/app.py` - `ping` (line 15)
- **Fingerprint:** `fp_f4181bf03bc78d06`

The handler at line 15 executes `subprocess.run` with a caller-supplied `host` value at line 24 with no authentication or authorization dependency. Input is validated by regex (line 21), but the operation remains accessible to any unauthenticated caller, enabling server-side network scanning and resource exhaustion.

**Evidence (citations):**

- `97b68ddb/app.py:15` - resolved
  > `def ping():`
- `97b68ddb/app.py:24` - resolved
  > `result = subprocess.run(['ping', '-c', '3', '--', host], capture_output=True, text=True, timeout=15)`

---

## 19. Unauthenticated ImageMagick invocation and thumbnail file creation  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `a651660b/app.py` - `create_thumbnail` (line 13)
- **Fingerprint:** `fp_ee70336664a389bd`

The handler defined at line 13 runs ImageMagick via `subprocess.run` at line 34 and writes a new thumbnail file to disk, with no authentication or authorization dependency in the shown code. Any unauthenticated caller can trigger server-side processing and persistent file writes.

**Evidence (citations):**

- `a651660b/app.py:13` - resolved
  > `def create_thumbnail():`
- `a651660b/app.py:34` - resolved
  > `result = subprocess.run(cmd, capture_output=True)`

---

## 20. CF-Connecting-IP trusted without verifying TCP peer is Cloudflare  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `ad57bc58/app.py` - `_client_ip_is_allowed` (line 9)
- **Fingerprint:** `fp_97b3f0135e6cb0a7`

Line 9 reads `CF-Connecting-IP` directly from the HTTP request headers. Because any HTTP client can set arbitrary request headers, an attacker can forge this value. There is no check anywhere in the shown code that `request.client.host` (the socket-level TCP peer) belongs to a trusted Cloudflare CIDR before the header value is accepted. The extracted IP is then used on line 16 to gate access to the office network, making the guard trivially bypassable.

**Evidence (citations):**

- `ad57bc58/app.py:9` - resolved
  > `cf_ip_raw = request.headers.get('CF-Connecting-IP', '').strip()`
- `ad57bc58/app.py:13` - resolved
  > `client_ip = ipaddress.ip_address(cf_ip_raw)`
- `ad57bc58/app.py:16` - resolved
  > `return client_ip in _OFFICE_NETWORK`

---

## 21. Metrics endpoint gated by spoofable header check  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `ad57bc58/app.py` - `metrics` (line 25)
- **Fingerprint:** `fp_fff78f14ab0076df`

The `/internal/metrics` endpoint on line 25 delegates its entire access control to `_client_ip_is_allowed(request)`, which is the function shown in unit 1 that blindly trusts the `CF-Connecting-IP` header. Because any attacker can send an arbitrary value for that header, the guard is bypassed by simply supplying an IP in the office CIDR range. The sensitive counter data is then returned on line 27.

**Evidence (citations):**

- `ad57bc58/app.py:25` - resolved
  > `if not _client_ip_is_allowed(request):`
- `ad57bc58/app.py:26` - resolved
  > `return JSONResponse(status_code=403, content={'detail': 'Forbidden'})`
- `ad57bc58/app.py:27` - resolved
  > `return COUNTERS`

---

## 22. CF-Connecting-IP trusted without verifying TCP peer is Cloudflare  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `b08cff37/app.py` - `_require_office_network` (line 8)
- **Fingerprint:** `fp_816c63903addd5b9`

Line 8 reads `CF-Connecting-IP` directly from request headers without first confirming the direct TCP peer is a legitimate Cloudflare proxy. The extracted string is parsed on line 10 and compared to the office network on line 13. An attacker connecting directly (not through Cloudflare) can set the header to any IP in the trusted range and bypass the restriction entirely.

**Evidence (citations):**

- `b08cff37/app.py:8` - resolved
  > `raw_ip = request.headers.get('CF-Connecting-IP', '').strip()`
- `b08cff37/app.py:10` - resolved
  > `client_ip = ipaddress.IPv4Address(raw_ip)`
- `b08cff37/app.py:13` - resolved
  > `if client_ip not in _OFFICE_NETWORK:`

---

## 23. Metrics endpoint gated by spoofable CF-Connecting-IP guard  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `b08cff37/app.py` - `metrics` (line 22)
- **Fingerprint:** `fp_a3e51c6526841e83`

The `metrics` function on line 22 returns `COUNTERS` with no inline auth check. Its access control depends entirely on `_require_office_network` (unit 5), which trusts the client-controlled `CF-Connecting-IP` header. An attacker who sends a forged header with an office-network IP will pass the guard and receive the metrics data.

**Evidence (citations):**

- `b08cff37/app.py:22` - resolved
  > `def metrics():`
- `b08cff37/app.py:23` - resolved
  > `return COUNTERS`

---

## 24. CF-Connecting-IP trusted without validating TCP peer is Cloudflare  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `f4e6f3b4/app.py` - `_get_real_client_ip` (line 8)
- **Fingerprint:** `fp_79962bdd41e5f3e7`

Line 8 reads `CF-Connecting-IP` from the request headers and line 10 returns it unconditionally as the real client IP, with no validation that `request.client.host` (line 12) falls within Cloudflare's published IP ranges. Any client that connects directly to the server (bypassing Cloudflare) can set `CF-Connecting-IP` to an arbitrary value and have it treated as their real IP, defeating any access-control logic that relies on this function.

**Evidence (citations):**

- `f4e6f3b4/app.py:8` - resolved
  > `cf_ip = request.headers.get('CF-Connecting-IP')`
- `f4e6f3b4/app.py:9` - resolved
  > `if cf_ip:`
- `f4e6f3b4/app.py:10` - resolved
  > `return cf_ip.strip()`
- `f4e6f3b4/app.py:11` - resolved
  > `if request.client:`
- `f4e6f3b4/app.py:12` - resolved
  > `return request.client.host`

---

## 25. Unauthenticated write operation creates server-side files  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `26b2ff78/app.py` - `create_thumbnail` (line 14)
- **Fingerprint:** `fp_be26866d85ba1c55`

Any unauthenticated caller can POST a filename and cause the server to invoke ImageMagick and write a thumbnail file to disk. No auth dependency is present in the shown code. While filename validation and path containment checks are in place, the fundamental issue is that an unauthenticated user can trigger server-side file creation.

**Evidence (citations):**

- `26b2ff78/app.py:14` - resolved
  > `def create_thumbnail():`
- `26b2ff78/app.py:18` - resolved
  > `filename = body['filename']`
- `26b2ff78/app.py:31` - resolved
  > `result = subprocess.run(['convert', source_path, '-thumbnail', '128x128', thumb_path], capture_output=True, timeout=30)`

---

## 26. Rightmost X-Forwarded-For value trusted without TCP-peer validation  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `27bec664/app.py` - `_get_client_ip` (line 13)
- **Fingerprint:** `fp_f99480446fff392d`

Using `[-1]` is a common attempt to mitigate leftmost-spoofing, but it remains exploitable when the server accepts direct connections: a client with no upstream proxy can craft `X-Forwarded-For: spoofed` and `xff.split(',')[-1].strip()` returns `spoofed`. Without verifying that `request.remote_addr` is a trusted proxy, both positions are attacker-controlled in a direct-connection scenario.

**Evidence (citations):**

- `27bec664/app.py:13` - resolved
  > `xff = request.headers.get('X-Forwarded-For', '')`
- `27bec664/app.py:15` - resolved
  > `return xff.split(',')[-1].strip()`

---

## 27. Unauthenticated access to MLflow run data  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `603948f1/app.py` - `artifacts_run` (line 15)
- **Fingerprint:** `fp_79a8bb2676d34e27`

The handler at line 15 calls `get_run(run_id)` at line 20 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can retrieve run data by supplying a valid artifact URI.

**Evidence (citations):**

- `603948f1/app.py:15` - resolved
  > `def artifacts_run(uri: str=Query(...)):`
- `603948f1/app.py:20` - resolved
  > `return get_run(run_id)`

---

## 28. Unauthenticated directory listing of uploaded images  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `6f8424d2/app.py` - `list_images` (line 9)
- **Fingerprint:** `fp_717e682a2a776afc`

The handler at line 9 returns a full directory listing of UPLOAD_DIR at line 10 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can enumerate uploaded filenames.

**Evidence (citations):**

- `6f8424d2/app.py:9` - resolved
  > `def list_images():`
- `6f8424d2/app.py:10` - resolved
  > `return jsonify(sorted(os.listdir(UPLOAD_DIR)))`

---

## 29. Unauthenticated listing of report filenames  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `7a053b8a/app.py` - `list_reports` (line 8)
- **Fingerprint:** `fp_a580fecf3b1ea975`

The endpoint returns the names of all files in `REPORTS_DIR` to any caller with no authentication or authorization check. Even without serving file contents, exposing report filenames can leak sensitive business or operational information (report names, dates, subjects) to unauthenticated parties.

**Evidence (citations):**

- `7a053b8a/app.py:8` - resolved
  > `def list_reports():`
- `7a053b8a/app.py:9` - resolved
  > `return sorted(os.listdir(REPORTS_DIR))`

---

## 30. Unauthenticated access to MLflow run data via URI path parsing  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `7bbd2eb1/app.py` - `artifacts_run` (line 10)
- **Fingerprint:** `fp_5be0749d18857c70`

The handler at line 10 parses an attacker-supplied URI and calls `get_run(run_id)` at line 16 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can retrieve run data.

**Evidence (citations):**

- `7bbd2eb1/app.py:10` - resolved
  > `def artifacts_run(uri: str=Query(..., description='mlflow-artifacts URI')):`
- `7bbd2eb1/app.py:16` - resolved
  > `return get_run(run_id)`

---

## 31. Unvalidated run_id extracted from URI passed directly to get_run  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-129  |  **Rule:** `codeguard-py-cwe-129`

- **Location:** `7bbd2eb1/app.py` - `artifacts_run` (line 13)
- **Fingerprint:** `fp_1de22feaf16a0f65`

After the `len(parts) < 2` guard, `parts[1]` is used as `run_id` without any format validation (e.g., UUID check, allowlist) before being forwarded to `get_run`. A crafted URI such as `mlflow-artifacts:///legitimate/../../admin` or one carrying SQL metacharacters would pass the length check and flow into `get_run` unchecked, making the risk dependent only on how `get_run` handles its argument.

**Evidence (citations):**

- `7bbd2eb1/app.py:13` - resolved
  > `if len(parts) < 2:`
- `7bbd2eb1/app.py:15` - resolved
  > `run_id = parts[1]`
- `7bbd2eb1/app.py:16` - resolved
  > `return get_run(run_id)`

---

## 32. Unauthenticated workspace directory listing  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `91113ebf/app.py` - `list_workspaces` (line 8)
- **Fingerprint:** `fp_3b60af19957682fb`

The handler at line 8 returns a full filesystem listing of WORKSPACE_ROOT at line 9 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can enumerate workspace names.

**Evidence (citations):**

- `91113ebf/app.py:8` - resolved
  > `def list_workspaces():`
- `91113ebf/app.py:9` - resolved
  > `return sorted(os.listdir(WORKSPACE_ROOT))`

---

## 33. Unauthenticated exposure of application settings  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `9152deb7/app.py` - `get_settings` (line 14)
- **Fingerprint:** `fp_aabe736ba3038dd3`

The handler at line 14 returns the `SETTINGS` object at line 15 with no authentication dependency and no locality restriction (unlike `reload_config` in the same file which calls `_require_local`). Any unauthenticated caller can retrieve potentially sensitive configuration.

**Evidence (citations):**

- `9152deb7/app.py:14` - resolved
  > `def get_settings():`
- `9152deb7/app.py:15` - resolved
  > `return SETTINGS`

---

## 34. Unauthenticated exposure of application settings  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `951d2c56/app.py` - `get_settings` (line 15)
- **Fingerprint:** `fp_4b32bed16130b896`

The handler at line 15 returns `SETTINGS` at line 16 with no authentication dependency and no locality check of any kind. Any unauthenticated remote caller can retrieve potentially sensitive configuration data.

**Evidence (citations):**

- `951d2c56/app.py:15` - resolved
  > `def get_settings():`
- `951d2c56/app.py:16` - resolved
  > `return SETTINGS`

---

## 35. Unauthenticated directory listing of uploaded images  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `a651660b/app.py` - `list_images` (line 9)
- **Fingerprint:** `fp_a399784ab94fbb47`

The handler at line 9 returns a full directory listing of UPLOAD_DIR at line 10 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can enumerate uploaded filenames.

**Evidence (citations):**

- `a651660b/app.py:9` - resolved
  > `def list_images():`
- `a651660b/app.py:10` - resolved
  > `return jsonify(sorted(os.listdir(UPLOAD_DIR)))`

---

## 36. Unauthenticated directory listing of report files  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `a7063cf4/app.py` - `list_reports` (line 8)
- **Fingerprint:** `fp_199dc99ed02a3d48`

The handler at line 8 returns a full filesystem listing of REPORTS_DIR at line 9 with no authentication or authorization dependency in the shown code. Any unauthenticated caller can enumerate report filenames, aiding targeted follow-on attacks.

**Evidence (citations):**

- `a7063cf4/app.py:8` - resolved
  > `def list_reports():`
- `a7063cf4/app.py:9` - resolved
  > `return sorted(os.listdir(REPORTS_DIR))`

---

## 37. Exception detail leaks internal filesystem path or subprocess info  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-209  |  **Rule:** `codeguard-py-error-info-leak`

- **Location:** `e9590724/app.py` - `create_thumbnail` (line 32)
- **Fingerprint:** `fp_c1a0e435d8a1564d`

Line 33 interpolates the raw caught exception into the JSON error response via an f-string: `f'Thumbnail creation failed: {exc}'`. The caught exception types are `FileNotFoundError` (whose string representation embeds the absolute filesystem path that was not found) and `subprocess.TimeoutExpired` (which can expose the command arguments including `src_real`). The `do_not_trigger_when` exclusion applies only to a broad `except Exception` pattern; here the except clause catches specific, semantically meaningful exceptions from a subprocess/filesystem call that commonly embed internal paths. This leaks internal path structure to unauthenticated callers.

**Evidence (citations):**

- `e9590724/app.py:32` - resolved
  > `except (FileNotFoundError, subprocess.TimeoutExpired) as exc:`
- `e9590724/app.py:33` - resolved
  > `return (jsonify({'error': f'Thumbnail creation failed: {exc}'}), 500)`
- `e9590724/app.py:31` - resolved
  > `result = subprocess.run(['convert', src_real, '-thumbnail', '128x128', thumb_path], capture_output=True, timeout=30)`

---

## 38. Rightmost X-Forwarded-For trusted without TCP peer validation  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `eeca267d/app.py` - `_get_client_ip` (line 13)
- **Fingerprint:** `fp_53bc193e09827cd7`

Line 13 reads the `X-Forwarded-For` header directly from untrusted client input and line 15 returns `xff.split(',')[-1].strip()` as the authoritative client IP. There is no check that `request.remote_addr` (the actual TCP peer) belongs to a known trusted proxy CIDR before trusting this header. Any client connecting directly—or through an arbitrary intermediary—can append an arbitrary value to the XFF header and have it returned as their identity, enabling IP spoofing for any downstream access-control check that consumes this value.

**Evidence (citations):**

- `eeca267d/app.py:13` - resolved
  > `xff = request.headers.get('X-Forwarded-For', '')`
- `eeca267d/app.py:15` - resolved
  > `return xff.split(',')[-1].strip()`
- `eeca267d/app.py:16` - resolved
  > `return request.remote_addr or ''`

---

## 39. Unauthenticated exposure of /proc/uptime  
**Verdict:** `true-positive`  |  **Severity:** `low`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `97b68ddb/app.py` - `uptime` (line 10)
- **Fingerprint:** `fp_e8bd00efa955c7ac`

The handler at line 10 opens and returns `/proc/uptime` at lines 11-12 with no authentication or authorization dependency. While uptime itself is low-sensitivity, it constitutes unauthenticated file access and contributes to information disclosure about server state.

**Evidence (citations):**

- `97b68ddb/app.py:10` - resolved
  > `def uptime():`
- `97b68ddb/app.py:11` - resolved
  > `with open('/proc/uptime') as fh:`
- `97b68ddb/app.py:12` - resolved
  > `return fh.read()`

---

## 40. File download endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `a7063cf4/app.py` - `download_report` (line 12)
- **Fingerprint:** `fp_23c2d6f46ef5eb0b`

The function signature `def download_report(file: str)` contains no FastAPI `Depends()` auth parameter, and the body contains no in-function auth check — only path-traversal guards. Whether a router-level dependency or middleware covers this endpoint cannot be determined from the shown lines alone, but the absence of any `Depends(...)` in the signature is a strong indicator. The operation is sensitive: it streams arbitrary files from disk to the caller.

**Evidence (citations):**

- `a7063cf4/app.py:12` - resolved
  > `def download_report(file: str):`
- `a7063cf4/app.py:19` - resolved
  > `return FileResponse(path=candidate, filename=os.path.basename(candidate), media_type='application/octet-stream')`

---

## 41. Orders report endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `b6ee94fe/app.py` - `orders_report` (line 16)
- **Fingerprint:** `fp_e39d891a72fdec3f`

The function `def orders_report()` contains no auth check in the shown lines and returns all matching order rows — potentially the entire `orders` table — to the caller via line 31. The use of parameterized queries prevents SQL injection, but there is no visible access control. Whether a Flask decorator or middleware applies auth is not determinable from the shown code.

**Evidence (citations):**

- `b6ee94fe/app.py:16` - resolved
  > `def orders_report():`
- `b6ee94fe/app.py:31` - resolved
  > `rows = get_db().execute(query, params).fetchall()`
- `b6ee94fe/app.py:32` - resolved
  > `return jsonify([dict(row) for row in rows])`

---

## 42. Thumbnail creation endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `b87d67fb/app.py` - `create_thumbnail` (line 13)
- **Fingerprint:** `fp_5157a35b4096f1de`

The function `def create_thumbnail()` performs a sensitive write operation — invoking ImageMagick's `convert` and writing a new file to `UPLOAD_DIR` — with no visible auth check in the shown lines. Unauthenticated file creation is a serious risk. Whether a decorator provides auth cannot be confirmed from the shown code.

**Evidence (citations):**

- `b87d67fb/app.py:13` - resolved
  > `def create_thumbnail():`
- `b87d67fb/app.py:28` - resolved
  > `result = subprocess.run(['convert', real_src, '-resize', '128x128!', thumb_path], capture_output=True)`
- `b87d67fb/app.py:31` - resolved
  > `return jsonify({'thumbnail': thumb_filename})`

---

## 43. Thumbnail creation endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `bd7a0432/app.py` - `create_thumbnail` (line 14)
- **Fingerprint:** `fp_7986d3cb234e1165`

The function `def create_thumbnail()` (bd7a0432) writes thumbnail files to disk via ImageMagick with no visible auth check in the shown lines. The operation is sensitive (file creation via external process). Whether a Flask decorator or middleware applies auth cannot be determined from the shown code.

**Evidence (citations):**

- `bd7a0432/app.py:14` - resolved
  > `def create_thumbnail():`
- `bd7a0432/app.py:33` - resolved
  > `subprocess.run(['convert', input_path, '-resize', '128x128', output_path], check=True, timeout=30, capture_output=True)`
- `bd7a0432/app.py:40` - resolved
  > `return (jsonify({'thumbnail': thumb_filename}), 201)`

---

## 44. Orders report endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `befcdf98/app.py` - `orders_report` (line 12)
- **Fingerprint:** `fp_2448ab91f8877fdb`

The function `def orders_report()` (befcdf98) returns all matching order rows to the caller on line 32 with no visible auth check. The query is constructed safely with parameterized inputs, but there is no access control guard in the shown code. Whether a Flask decorator or hook applies auth cannot be confirmed.

**Evidence (citations):**

- `befcdf98/app.py:12` - resolved
  > `def orders_report():`
- `befcdf98/app.py:32` - resolved
  > `rows = get_db().execute(query, params).fetchall()`
- `befcdf98/app.py:33` - resolved
  > `return jsonify([dict(row) for row in rows])`

---

## 45. Missing auth in delete_workspace – route decorator not shown  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `d158186f/app.py` - `delete_workspace` (line 19)
- **Fingerprint:** `fp_25a5eb150acb9ab5`

The function body performs a destructive `shutil.rmtree` at line 19 with no in-body authentication or authorization check. However, FastAPI auth is typically injected via `Depends()` in the route decorator, which is not included in the shown lines. Absence of in-body auth is necessary but not sufficient to confirm CWE-862; the route-level definition must be inspected to verify no `Depends(get_current_user)` or similar guard exists.

**Evidence (citations):**

- `d158186f/app.py:19` - resolved
  > `shutil.rmtree(workspace_path)`
- `d158186f/app.py:12` - resolved
  > `def delete_workspace(name: str):`

---

## 46. Missing auth in delete_workspace – route decorator not shown  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `d49606d8/app.py` - `delete_workspace` (line 21)
- **Fingerprint:** `fp_9dd7dec78540ba92`

The function executes `shutil.rmtree(workspace_path)` at line 21 with no in-body auth check. As with candidate 0, the route decorator containing any `Depends()` guard is not shown. The path-traversal guard on line 13 is present, but that does not address authorization.

**Evidence (citations):**

- `d49606d8/app.py:21` - resolved
  > `shutil.rmtree(workspace_path)`
- `d49606d8/app.py:12` - resolved
  > `def delete_workspace(name: str):`

---

## 47. Missing auth in delete_workspace – route decorator not shown  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `edcbd6a2/app.py` - `delete_workspace` (line 21)
- **Fingerprint:** `fp_e63b89fe30bc8826`

The function calls `shutil.rmtree(target)` at line 21 with no in-body auth check. The path-containment guard at line 15 addresses traversal but not authorization. The route decorator with any `Depends()` guard is not present in the shown lines.

**Evidence (citations):**

- `edcbd6a2/app.py:21` - resolved
  > `shutil.rmtree(target)`
- `edcbd6a2/app.py:12` - resolved
  > `def delete_workspace(name: str):`

---

## 48. Object-storage key passed to delete_object without traversal check  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `15fa94ff/app.py` - `delete_file` (line 17)
- **Fingerprint:** `fp_c45cf5d92e1bece4`

The structural validation confirms `parts[0] == 'tenants'` and `parts[2] == 'files'`, but a key like `tenants/foo/files/../../../other-tenant/files/secret` would pass those checks and be forwarded verbatim to `delete_object`. Exploitability depends on whether `delete_object` resolves the key against a filesystem or treats it as a literal cloud-storage key; the implementation is not shown.

**Evidence (citations):**

- `15fa94ff/app.py:17` - resolved
  > `if len(parts) < 4 or parts[0] != 'tenants' or parts[2] != 'files':`
- `15fa94ff/app.py:23` - resolved
  > `delete_object(key)`

---

## 49. Access control depends on _get_real_client_ip whose implementation is not shown  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `242c4d0f/app.py` - `metrics` (line 32)
- **Fingerprint:** `fp_4612b95fe4eea18b`

The metrics endpoint enforces a CIDR check against the result of `_get_real_client_ip(request)`, but the body of that function is not included in the shown source. Whether it properly validates the TCP peer before trusting any forwarded-for header cannot be determined from the visible lines alone.

**Evidence (citations):**

- `242c4d0f/app.py:32` - resolved
  > `client_ip_str = _get_real_client_ip(request)`
- `242c4d0f/app.py:37` - resolved
  > `if client_addr not in _OFFICE_CIDR:`

---

## 50. Possible bypass of _require_local if deployed behind reverse proxy  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-346  |  **Rule:** `codeguard-py-cwe-346`

- **Location:** `9152deb7/app.py` - `reload_config` (line 18)
- **Fingerprint:** `fp_32580e65bcff4b0d`

The handler at line 18 delegates its locality check entirely to `_require_local(request)` at line 19, whose implementation is not shown. Whether it reads `request.client.host` (socket-level peer) or trusts `X-Forwarded-For` cannot be confirmed from the shown lines alone. If the implementation trusts a proxy-injected header, a remote caller can spoof locality; if it uses only the TCP peer, the check is sound. A review of `_require_local` is required to confirm or rule out CWE-346.

**Evidence (citations):**

- `9152deb7/app.py:18` - resolved
  > `def reload_config(request: Request):`
- `9152deb7/app.py:19` - resolved
  > `_require_local(request)`

---

## 51. Ping endpoint exposes network output without visible auth  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `ae9f5403/app.py` - `ping` (line 13)
- **Fingerprint:** `fp_453753d4f668419e`

The function signature `def ping()` and body show no authentication check. The endpoint executes `subprocess.run(['ping', '-c', '3', '--', host], ...)` and returns the full stdout+stderr on line 18, which can reveal internal hostnames and network topology. Whether a Flask decorator provides auth is not visible in the shown lines. Input validation via `_SAFE_HOST_RE` is present but does not substitute for access control.

**Evidence (citations):**

- `ae9f5403/app.py:13` - resolved
  > `def ping():`
- `ae9f5403/app.py:17` - resolved
  > `result = subprocess.run(['ping', '-c', '3', '--', host], capture_output=True, text=True, timeout=15)`
- `ae9f5403/app.py:18` - resolved
  > `output = result.stdout + result.stderr`

---

## 52. Order count endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `b6ee94fe/app.py` - `count_orders` (line 11)
- **Fingerprint:** `fp_5913de3a75d51397`

The function `def count_orders()` has no visible auth check in its body, and no Flask decorator context is shown. It queries and returns a business-sensitive aggregate from the orders table. Whether a `before_request` hook or route decorator restricts access cannot be determined from the shown lines.

**Evidence (citations):**

- `b6ee94fe/app.py:11` - resolved
  > `def count_orders():`
- `b6ee94fe/app.py:12` - resolved
  > `n, = get_db().execute('SELECT COUNT(*) FROM orders').fetchone()`
- `b6ee94fe/app.py:13` - resolved
  > `return jsonify({'count': n})`

---

## 53. Image listing endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `b87d67fb/app.py` - `list_images` (line 9)
- **Fingerprint:** `fp_e047d80f5df68c23`

The function `def list_images()` has no auth check in the shown lines and returns a full sorted directory listing via `os.listdir`. This exposes the names of all uploaded files to any caller. Whether Flask-level auth is applied via a decorator cannot be confirmed from the shown code.

**Evidence (citations):**

- `b87d67fb/app.py:9` - resolved
  > `def list_images():`
- `b87d67fb/app.py:10` - resolved
  > `return jsonify(sorted(os.listdir(UPLOAD_DIR)))`

---

## 54. Image listing endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `bd7a0432/app.py` - `list_images` (line 10)
- **Fingerprint:** `fp_41575880aa21baaa`

The function `def list_images()` (bd7a0432) returns a sorted directory listing of all uploaded files with no visible auth check. Whether Flask-level auth is applied via a decorator or `before_request` hook cannot be confirmed from the shown lines alone.

**Evidence (citations):**

- `bd7a0432/app.py:10` - resolved
  > `def list_images():`
- `bd7a0432/app.py:11` - resolved
  > `return jsonify(sorted(os.listdir(UPLOAD_DIR)))`

---

## 55. Settings endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `c8367c9e/app.py` - `get_settings` (line 10)
- **Fingerprint:** `fp_4af57da9a384ff77`

The function `def get_settings()` (c8367c9e) returns the full `SETTINGS` dict on line 11 with no visible auth check. If SETTINGS contains sensitive configuration values (API keys, internal parameters) and the sibling admin endpoint is restricted, the asymmetry suggests this endpoint should also be protected. Whether a decorator or middleware applies auth is not visible in the shown lines.

**Evidence (citations):**

- `c8367c9e/app.py:10` - resolved
  > `def get_settings():`
- `c8367c9e/app.py:11` - resolved
  > `return SETTINGS`

---

## 56. Settings endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `c894ab1e/app.py` - `get_settings` (line 14)
- **Fingerprint:** `fp_1eafce99cd80ed33`

The function `def get_settings()` (c894ab1e) returns the full `SETTINGS` dict on line 15 with no visible auth check. If the companion admin endpoint is guarded, this endpoint's lack of visible auth represents a potential asymmetry. The contents of `SETTINGS` are unknown from the shown code, making full impact assessment impossible without more context.

**Evidence (citations):**

- `c894ab1e/app.py:14` - resolved
  > `def get_settings():`
- `c894ab1e/app.py:15` - resolved
  > `return SETTINGS`

---

## 57. SETTINGS object may expose sensitive configuration values  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-312  |  **Rule:** `codeguard-py-sensitive-data-exposure`

- **Location:** `ca7f39db/app.py` - `get_settings` (line 9)
- **Fingerprint:** `fp_5951e5aba5cfbdd4`

Line 10 returns `SETTINGS` directly to the caller with no filtering or redaction. The actual contents of `SETTINGS` are not visible in the shown lines, so whether it contains secrets, API keys, or other sensitive values cannot be confirmed. If it does, this constitutes CWE-312 (cleartext storage/exposure of sensitive information). The verdict depends on data-flow context not shown.

**Evidence (citations):**

- `ca7f39db/app.py:9` - resolved
  > `def get_settings():`
- `ca7f39db/app.py:10` - resolved
  > `return SETTINGS`

---

## 58. Settings endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `ca7f39db/app.py` - `get_settings` (line 9)
- **Fingerprint:** `fp_8ba4b87986396680`

The function `def get_settings()` (ca7f39db) contains no auth check in the shown lines and returns the full `SETTINGS` object. Whether a Flask decorator or middleware restricts access cannot be confirmed from the shown code. The sensitivity of the exposed data depends on the contents of `SETTINGS`, which are not visible.

**Evidence (citations):**

- `ca7f39db/app.py:9` - resolved
  > `def get_settings():`
- `ca7f39db/app.py:10` - resolved
  > `return SETTINGS`

---

## 59. Reports listing endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `cbbf0736/app.py` - `list_reports` (line 8)
- **Fingerprint:** `fp_17e134b5c1f79e96`

The function `def list_reports()` returns a sorted `os.listdir` of the reports directory on line 9 with no visible auth check. This exposes the names of all report files to any caller. Whether a Flask decorator or `before_request` hook applies auth cannot be determined from the shown lines.

**Evidence (citations):**

- `cbbf0736/app.py:8` - resolved
  > `def list_reports():`
- `cbbf0736/app.py:9` - resolved
  > `return sorted(os.listdir(REPORTS_DIR))`

---

## 60. Workspace listing endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `d158186f/app.py` - `list_workspaces` (line 8)
- **Fingerprint:** `fp_7f476a0e17acfddb`

The function `def list_workspaces()` returns a sorted `os.listdir` of the workspace root on line 9 with no visible auth check. This exposes the names of all workspace directories to any unauthenticated caller. Whether a Flask decorator or middleware applies auth cannot be determined from the shown lines.

**Evidence (citations):**

- `d158186f/app.py:8` - resolved
  > `def list_workspaces():`
- `d158186f/app.py:9` - resolved
  > `return sorted(os.listdir(WORKSPACE_ROOT))`

---

## 61. Missing auth in get_settings – route decorator not shown  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `dd03b72c/app.py` - `get_settings` (line 10)
- **Fingerprint:** `fp_e077440d27466426`

The function at line 10 has no in-body auth check and returns potentially sensitive configuration at line 11. The route decorator with any `Depends()` guard is not present in the shown lines, so the presence or absence of framework-level auth cannot be confirmed.

**Evidence (citations):**

- `dd03b72c/app.py:10` - resolved
  > `def get_settings():`
- `dd03b72c/app.py:11` - resolved
  > `return SETTINGS`

---

## 62. Possible sensitive data exposure via SETTINGS – content unknown  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-312  |  **Rule:** `codeguard-py-sensitive-data-exposure`

- **Location:** `dd03b72c/app.py` - `get_settings` (line 11)
- **Fingerprint:** `fp_013a71630df88395`

Line 11 returns the entire `SETTINGS` object to the caller. Whether this constitutes CWE-312 depends entirely on what `SETTINGS` contains (e.g., API keys, DB passwords, internal hostnames). The shown source does not reveal the definition or contents of `SETTINGS`, so the severity cannot be confirmed without that context.

**Evidence (citations):**

- `dd03b72c/app.py:11` - resolved
  > `return SETTINGS`

---

## 63. Unauthenticated listing of upload-directory filenames  
**Verdict:** `needs-review`  |  **Severity:** `low`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `26b2ff78/app.py` - `list_images` (line 10)
- **Fingerprint:** `fp_98469c928a449f89`

The handler returns all filenames in `UPLOAD_DIR` to any caller without authentication. Sensitivity depends on whether those filenames are considered private (e.g., user-uploaded content whose existence should not be disclosed). No auth dependency is visible in the shown lines, but whether this constitutes a genuine security defect depends on the application's privacy requirements.

**Evidence (citations):**

- `26b2ff78/app.py:10` - resolved
  > `def list_images():`
- `26b2ff78/app.py:11` - resolved
  > `return jsonify(sorted(os.listdir(UPLOAD_DIR)))`

---

## 64. User-supplied basename used as Content-Disposition filename without CR/LF stripping  
**Verdict:** `needs-review`  |  **Severity:** `low`  |  **Class:** CWE-113  |  **Rule:** `codeguard-py-header-injection`

- **Location:** `7a053b8a/app.py` - `download_report` (line 13)
- **Fingerprint:** `fp_0c62b0845a9eae8f`

`os.path.basename` strips directory separators but does not remove CR/LF or quote characters; these could break the `Content-Disposition` header if passed through to `FileResponse`. Exploitability depends on whether Starlette/FastAPI's `FileResponse` properly encodes the `filename` parameter; the framework's behavior is not visible in the shown lines.

**Evidence (citations):**

- `7a053b8a/app.py:13` - resolved
  > `safe_name = os.path.basename(file)`
- `7a053b8a/app.py:22` - resolved
  > `return FileResponse(file_path, filename=safe_name)`

---

## 65. Uptime endpoint may lack authentication  
**Verdict:** `needs-review`  |  **Severity:** `low`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `ae9f5403/app.py` - `uptime` (line 8)
- **Fingerprint:** `fp_11e3a73992d1f00f`

No auth check or decorator is visible in the shown lines. The function reads a system-level file and returns its raw contents. However, `/proc/uptime` carries minimal sensitivity (it reveals server uptime only), so the practical impact is low. Whether a Flask `before_request` hook or route decorator provides authentication cannot be determined from the shown code alone.

**Evidence (citations):**

- `ae9f5403/app.py:8` - resolved
  > `def uptime():`
- `ae9f5403/app.py:9` - resolved
  > `with open('/proc/uptime') as fh:`
- `ae9f5403/app.py:10` - resolved
  > `return fh.read()`

---

## 66. Missing auth in list_workspaces – route decorator not shown  
**Verdict:** `needs-review`  |  **Severity:** `low`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `d49606d8/app.py` - `list_workspaces` (line 9)
- **Fingerprint:** `fp_d63e48fdbf54816b`

The function returns directory contents at line 9 with no in-body auth check. FastAPI can enforce auth at the route decorator level via `Depends()`, which is not visible in the shown source. The operation itself (directory listing) is lower sensitivity than deletion but still warrants verification of the route definition.

**Evidence (citations):**

- `d49606d8/app.py:9` - resolved
  > `return sorted(os.listdir(WORKSPACE_ROOT))`

---

## 67. Missing auth in list_workspaces – route decorator not shown  
**Verdict:** `needs-review`  |  **Severity:** `low`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `edcbd6a2/app.py` - `list_workspaces` (line 9)
- **Fingerprint:** `fp_ca4a49af48635363`

The function returns directory contents via `os.listdir(WORKSPACE_ROOT)` at line 9 with no in-body auth. The route-level decorator that could supply a `Depends()` guard is not shown. Needs confirmation from the route definition.

**Evidence (citations):**

- `edcbd6a2/app.py:9` - resolved
  > `return sorted(os.listdir(WORKSPACE_ROOT))`

---

## 68. /proc/uptime is non-sensitive; missing-authz rule does not apply  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `25734010/app.py` - `uptime` (line 8)
- **Fingerprint:** `fp_d516c9322c07b3c4`

`/proc/uptime` is a Linux pseudo-file that exposes only the system's uptime in seconds—no credentials, no PII, no system configuration. The rule's trigger requires the operation to be sensitive (write, delete, code execution, file access to secret data); reading system uptime does not meet that threshold.

**Evidence (citations):**

- `25734010/app.py:8` - resolved
  > `with open('/proc/uptime') as fh:`
- `25734010/app.py:9` - resolved
  > `return fh.read()`

---

## 69. /proc/uptime is non-sensitive; missing-authz rule does not apply  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `380e9e71/app.py` - `uptime` (line 9)
- **Fingerprint:** `fp_32bcd38a1343db31`

`/proc/uptime` exposes only elapsed seconds since boot—no credentials, configuration, or PII. The missing-authz rule requires the operation to be sensitive; reading system uptime does not qualify under any of the enumerated sensitive categories.

**Evidence (citations):**

- `380e9e71/app.py:9` - resolved
  > `with open('/proc/uptime') as fh:`
- `380e9e71/app.py:10` - resolved
  > `return fh.read()`

---

## 70. Aggregate order count is not a sensitive operation  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `6f9598ee/app.py` - `count_orders` (line 31)
- **Fingerprint:** `fp_7b7f722756fbb9aa`

The endpoint returns a single integer count of rows in the orders table. The missing-authz rule's trigger requires the operation to be sensitive (write, delete, code execution, file access, or secret retrieval). Returning a scalar aggregate count does not meet any of those criteria; no order records, PII, or credentials are exposed.

**Evidence (citations):**

- `6f9598ee/app.py:31` - resolved
  > `n, = get_db().execute('SELECT COUNT(*) FROM orders').fetchone()`
- `6f9598ee/app.py:32` - resolved
  > `return jsonify({'count': n})`

---

## 71. Array index access is guarded; CWE-129 does not apply  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-129  |  **Rule:** `codeguard-py-cwe-129`

- **Location:** `a0723745/app.py` - `delete_file` (line 17)
- **Fingerprint:** `fp_5321d3d73a398e30`

Line 17 explicitly checks `len(parts) < 4` before any indexed access, ensuring `parts[0]`, `parts[1]`, and `parts[2]` are always within bounds. The extracted `key_tenant` at line 19 is used only in a string equality comparison at line 21 against `caller_tenant`, which is a well-defined access-control check rather than an improper array-index use. The trigger_when criterion requiring unguarded indexing is not met.

**Evidence (citations):**

- `a0723745/app.py:17` - resolved
  > `if len(parts) < 4 or parts[0] != 'tenants' or parts[2] != 'files':`
- `a0723745/app.py:19` - resolved
  > `key_tenant = parts[1]`
- `a0723745/app.py:21` - resolved
  > `if key_tenant != caller_tenant:`

---
