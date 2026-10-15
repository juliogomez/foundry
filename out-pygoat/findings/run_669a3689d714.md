# Foundry PoC - security findings report

- **Run:** `run_669a3689d714`
- **Target:** `pygoat` @ `master`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 180  |  **Candidates:** 47  |  **Tokens:** 420358/2000000
- **Stop reason:** coverage-complete (all 180 units); trailing true-positive yield=0.92

## Summary

| Verdict | Count |
|---|---|
| true-positive | 42 |
| needs-review | 3 |
| false-positive | 2 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Unsafe pickle deserialization of attacker-controlled form data (RCE)  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-502  |  **Rule:** `codeguard-py-unsafe-deserialization`

- **Location:** `dockerized_labs/insec_des_lab/main.py` - `deserialize_data` (line 33)
- **Fingerprint:** `fp_b4ca54e54a531181`

Line 33 reads `serialized_data` directly from a POST form field; line 34 base64-decodes it with no validation; line 36 passes the result to `pickle.loads` with no integrity check or class restriction. An attacker can submit a crafted pickle payload implementing `__reduce__` to execute arbitrary OS commands on the server. There is no allowlist, HMAC signature, or other trust boundary protecting this deserialization call.

**Evidence (citations):**

- `dockerized_labs/insec_des_lab/main.py:33` - resolved
  > `serialized_data = request.form.get('serialized_data', '')`
- `dockerized_labs/insec_des_lab/main.py:34` - resolved
  > `decoded_data = base64.b64decode(serialized_data)`
- `dockerized_labs/insec_des_lab/main.py:36` - resolved
  > `user = pickle.loads(decoded_data)`

---

## 2. Missing authentication/authorization on all-users data endpoint  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `dockerized_labs/sensitive_data_exposure/dataexposure/views.py` - `all_users_data_view` (line 113)
- **Fingerprint:** `fp_96c485caa6a4013b`

The view at line 112 contains no authentication or authorization guard before querying and returning all users' records. Lines 129–130, commented out, acknowledge exactly what is missing: `if not request.user.is_authenticated or not request.user.is_staff`. Any unauthenticated HTTP request to this endpoint receives every user's sensitive data in a single JSON response.

**Evidence (citations):**

- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:113` - resolved
  > `# MAJOR SECURITY FLAW: This endpoint allows ANY user (even unauthenticated ones!)`
- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:129` - resolved
  > `# if not request.user.is_authenticated or not request.user.is_staff:`
- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:132` - resolved
  > `return JsonResponse({'users': all_users_data})`

---

## 3. All users' unmasked PII and secrets exposed in unauthenticated JSON response  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-312  |  **Rule:** `codeguard-py-sensitive-data-exposure`

- **Location:** `dockerized_labs/sensitive_data_exposure/dataexposure/views.py` - `all_users_data_view` (line 123)
- **Fingerprint:** `fp_f5238a2711d206e4`

Lines 123–125 append raw, unmasked credit card numbers, SSNs, and API keys for every user record into a list returned to any caller. The inline comments on those same lines explicitly acknowledge the severity ('Completely exposed! No masking!', 'Sending full SSN - terrible practice!'). Combined with the missing authorization check (candidate 5), this constitutes a complete, unauthenticated bulk exfiltration path for all users' sensitive financial and identity data.

**Evidence (citations):**

- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:123` - resolved
  > `'credit_card': user_data.credit_card,  # Completely exposed! No masking!`
- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:124` - resolved
  > `'ssn': user_data.ssn,  # Sending full SSN - terrible practice!`
- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:125` - resolved
  > `'api_key': user_data.api_key  # API keys should never be exposed like this`

---

## 4. Arbitrary code injection via write of POST body to .py source file  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `introduction/apis.py` - `A6_disscussion_api_2` (line 130)
- **Fingerprint:** `fp_961ecc085843a429`

Attacker-supplied POST field 'code' is written verbatim to a Python source file on disk. When the application subsequently imports or executes that file it will run the injected code with the process's privileges. No sandboxing, allowlist, or AST validation is applied before writing.

**Evidence (citations):**

- `introduction/apis.py:130` - resolved
  > `code = request.POST.get('code')`
- `introduction/apis.py:133` - resolved
  > `f = open(filename,"w")`
- `introduction/apis.py:134` - resolved
  > `f.write(code)`

---

## 5. Missing authentication on eval() endpoint mitre_lab_25_api  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/mitre.py` - `mitre_lab_25_api` (line 215)
- **Fingerprint:** `fp_c52150ca1bcf8be4`

No authentication decorator or in-body check appears anywhere in lines 215-221. Combined with the eval() call on POST input, any unauthenticated external caller can trigger arbitrary code execution.

**Evidence (citations):**

- `introduction/mitre.py:215` - resolved
  > `def mitre_lab_25_api(request):`
- `introduction/mitre.py:217` - resolved
  > `expression = request.POST.get('expression')`
- `introduction/mitre.py:218` - resolved
  > `result = eval(expression)`

---

## 6. Unsandboxed eval() on user-supplied POST parameter  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `introduction/mitre.py` - `mitre_lab_25_api` (line 217)
- **Fingerprint:** `fp_e64d969c73a03b0a`

The POST field 'expression' is passed without any filtering or restricted globals directly to eval(). This allows any caller to execute arbitrary Python in the server process, with access to the full runtime environment.

**Evidence (citations):**

- `introduction/mitre.py:217` - resolved
  > `expression = request.POST.get('expression')`
- `introduction/mitre.py:218` - resolved
  > `result = eval(expression)`

---

## 7. Missing authentication on mitre_lab_17_api exposes shell injection to unauthenticated callers  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/mitre.py` - `mitre_lab_17_api` (line 238)
- **Fingerprint:** `fp_d1d235186210ca52`

No authentication check appears in lines 238-247. Any unauthenticated HTTP caller can POST an ip value containing shell metacharacters and achieve arbitrary command execution on the server via the nmap concatenation.

**Evidence (citations):**

- `introduction/mitre.py:238` - resolved
  > `def mitre_lab_17_api(request):`
- `introduction/mitre.py:240` - resolved
  > `ip = request.POST.get('ip')`
- `introduction/mitre.py:241` - resolved
  > `command = "nmap " + ip`

---

## 8. OS command injection via unsanitized POST 'ip' in nmap command  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `introduction/mitre.py` - `mitre_lab_17_api` (line 240)
- **Fingerprint:** `fp_7c7254bc3aef7266`

The POST parameter 'ip' is concatenated directly into the string 'nmap ' + ip with no validation, then passed to command_out which calls subprocess.Popen with shell=True. An attacker can append shell metacharacters (e.g., ; id, | cat /etc/passwd) to execute arbitrary OS commands.

**Evidence (citations):**

- `introduction/mitre.py:240` - resolved
  > `ip = request.POST.get('ip')`
- `introduction/mitre.py:241` - resolved
  > `command = "nmap " + ip`
- `introduction/mitre.py:242` - resolved
  > `res, err = command_out(command)`
- `introduction/mitre.py:233` - resolved
  > `process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)`

---

## 9. SQL injection via string concatenation of name and password into raw query  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-89  |  **Rule:** `codeguard-py-sql-injection`

- **Location:** `introduction/views.py` - `sql_lab` (line 150)
- **Fingerprint:** `fp_261ef672e9351bd1`

Both 'name' and 'password' from request.POST are concatenated directly into a raw SQL string that is passed to login.objects.raw(). There is no parameterized binding, allowing classic SQL injection payloads to alter query logic.

**Evidence (citations):**

- `introduction/views.py:150` - resolved
  > `name=request.POST.get('name')`
- `introduction/views.py:152` - resolved
  > `password=request.POST.get('pass')`
- `introduction/views.py:158` - resolved
  > `sql_query = "SELECT * FROM introduction_login WHERE user='"+name+"' AND password='"+password+"'"`
- `introduction/views.py:162` - resolved
  > `val=login.objects.raw(sql_query)`

---

## 10. Unsafe pickle deserialization of attacker-controlled cookie  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-502  |  **Rule:** `codeguard-py-unsafe-deserialization`

- **Location:** `introduction/views.py` - `insec_des_lab` (line 208)
- **Fingerprint:** `fp_d24a222be6e31b71`

The 'token' cookie is base64-decoded and fed directly to pickle.loads() with no HMAC or signature verification. An attacker can craft a malicious pickle payload in a cookie, causing arbitrary Python code execution during deserialization.

**Evidence (citations):**

- `introduction/views.py:208` - resolved
  > `token = request.COOKIES.get('token')`
- `introduction/views.py:213` - resolved
  > `token = base64.b64decode(token)`
- `introduction/views.py:214` - resolved
  > `admin = pickle.loads(token)`

---

## 11. OS command injection via domain POST parameter in shell command  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `introduction/views.py` - `cmd_lab` (line 418)
- **Fingerprint:** `fp_b77769a7adf83016`

The 'domain' value from request.POST is substituted into a shell command string with .format() and then passed to subprocess.Popen with shell=True. The regex at line 420 only strips URL schemes and 'www.' prefixes; it does not remove shell metacharacters such as semicolons, pipes, or backticks, leaving the injection surface fully open.

**Evidence (citations):**

- `introduction/views.py:418` - resolved
  > `domain=request.POST.get('domain')`
- `introduction/views.py:420` - resolved
  > `domain = re.sub(r'^(?:(https?|ftp)://)?(?:www\.)?', '', domain, flags=re.IGNORECASE)`
- `introduction/views.py:424` - resolved
  > `command="nslookup {}".format(domain)`
- `introduction/views.py:426` - resolved
  > `command = "dig {}".format(domain)`
- `introduction/views.py:432` - resolved
  > `shell=True,`

---

## 12. Unsandboxed eval() on user-supplied POST parameter 'val'  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `introduction/views.py` - `cmd_lab2` (line 456)
- **Fingerprint:** `fp_3aac87bc7ebe32dd`

The POST field 'val' is passed with no filtering or restricted globals/locals directly to eval(). This permits an authenticated attacker to execute arbitrary Python inside the server process.

**Evidence (citations):**

- `introduction/views.py:456` - resolved
  > `val=request.POST.get('val')`
- `introduction/views.py:460` - resolved
  > `output = eval(val)`

---

## 13. Code injection via user-supplied expression in ImageMath.eval()  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `introduction/views.py` - `a9_lab2` (line 583)
- **Fingerprint:** `fp_d9ab80320100c951`

The POST field 'function' is passed without sanitization to ImageMath.eval(), which executes the string as Python code internally. There is no allowlist or restricted execution environment, enabling arbitrary code execution through a crafted function string.

**Evidence (citations):**

- `introduction/views.py:583` - resolved
  > `function_str = request.POST.get("function")`
- `introduction/views.py:588` - resolved
  > `output = ImageMath.eval(function_str,img = img, b=b, r=r, g=g)`

---

## 14. SQL Injection via unsanitized POST parameters in raw query  
**Verdict:** `true-positive`  |  **Severity:** `critical`  |  **Class:** CWE-89  |  **Rule:** `codeguard-py-sql-injection`

- **Location:** `introduction/views.py` - `injection_sql_lab` (line 858)
- **Fingerprint:** `fp_a15f675062374add`

User-supplied `name` and `password` POST fields are read without sanitization and concatenated directly into a raw SQL string. That string is then executed verbatim via `objects.raw()` with no parameterization, allowing an attacker to inject arbitrary SQL clauses.

**Evidence (citations):**

- `introduction/views.py:858` - resolved
  > `name=request.POST.get('name')`
- `introduction/views.py:859` - resolved
  > `password=request.POST.get('pass')`
- `introduction/views.py:864` - resolved
  > `sql_query = "SELECT * FROM introduction_sql_lab_table WHERE id='"+name+"'AND password='"+password+"'"`
- `introduction/views.py:878` - resolved
  > `user = sql_lab_table.objects.raw(sql_query)`

---

## 15. Argument injection via docker_image/docker_port in subprocess.Popen  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `challenge/views.py` - `DoItFast.post` (line 33)
- **Fingerprint:** `fp_ad5215ed2a378542`

The f-string on line 49 interpolates `chal.docker_port` and `chal.docker_image` directly from a database-backed model record into a command string, which is then split on spaces and passed to Popen. Although `shell=True` is absent (preventing classic shell metacharacter injection), splitting a string containing spaces yields extra argv entries, enabling argument injection—e.g., a `docker_image` value of `ubuntu --privileged -v /:/host` would expand into additional Docker flags. The challenge record is keyed by a URL parameter (`challenge/views.py` line 33), making the attack surface reachable from an external caller who can influence database records.

**Evidence (citations):**

- `challenge/views.py:33` - resolved
  > `chal = Challenge.objects.get(name=challenge)`
- `challenge/views.py:49` - resolved
  > `command = f"docker run -d -p {port}:{chal.docker_port} {chal.docker_image}"`
- `challenge/views.py:50` - resolved
  > `process = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)`

---

## 16. MD5 used for password reset token generation (weak cryptography)  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-327  |  **Rule:** `codeguard-py-weak-crypto`

- **Location:** `dockerized_labs/broken_auth_lab/app.py` - `reset_password` (line 86)
- **Fingerprint:** `fp_8036ca6a4c0d5067`

Line 86 uses `hashlib.md5` to derive a password reset token from an email address and the current timestamp. MD5 is cryptographically broken and its small output space (128 bits) combined with a predictable input (`email:datetime.now()`) makes the token vulnerable to brute-force or preimage attacks. The token is then stored and exposed directly in the flash message on line 91, compounding the weakness by leaking it in the HTTP response.

**Evidence (citations):**

- `dockerized_labs/broken_auth_lab/app.py:86` - resolved
  > `token = hashlib.md5(f"{email}:{datetime.now()}".encode()).hexdigest()`
- `dockerized_labs/broken_auth_lab/app.py:91` - resolved
  > `flash(f'Password reset link: /reset/{token}')`

---

## 17. Plaintext sensitive data (credit card, SSN, API key) returned in API response  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-312  |  **Rule:** `codeguard-py-sensitive-data-exposure`

- **Location:** `dockerized_labs/sensitive_data_exposure/dataexposure/views.py` - `api_data_view` (line 103)
- **Fingerprint:** `fp_9b6507ea3c022ff6`

Lines 103–105 place the raw, unmasked credit card number, SSN, and API key directly into a `JsonResponse` dict with no redaction, truncation, or encryption. Line 96–98 show that even fallback-created dummy records store these values in plaintext. While the endpoint requires an authenticated session (line 91 uses `request.user`), returning full PAN, SSN, and API key in a JSON response violates PCI-DSS/data minimization principles and exposes secrets to any network observer or XSS attacker.

**Evidence (citations):**

- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:103` - resolved
  > `'credit_card': user_data.credit_card,`
- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:104` - resolved
  > `'ssn': user_data.ssn,`
- `dockerized_labs/sensitive_data_exposure/dataexposure/views.py:105` - resolved
  > `'api_key': user_data.api_key`

---

## 18. Unauthenticated write to server-side Python source files  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/apis.py` - `log_function_checker` (line 61)
- **Fingerprint:** `fp_0a48516757799842`

log_function_checker contains no authentication decorator and no in-body check such as request.user.is_authenticated. Any anonymous caller can POST arbitrary log_code and api_code, which are written verbatim to server-side Python source files. The subsequent HTTP requests (lines 81–84) then cause the server to execute the injected code.

**Evidence (citations):**

- `introduction/apis.py:61` - resolved
  > `def log_function_checker(request):`
- `introduction/apis.py:62` - resolved
  > `if request.method == 'POST':`
- `introduction/apis.py:70` - resolved
  > `f.write(log_code)`
- `introduction/apis.py:73` - resolved
  > `f.write(api_code)`

---

## 19. Unauthenticated overwrite of server-side Python source file  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/apis.py` - `A6_disscussion_api_2` (line 126)
- **Fingerprint:** `fp_c5d46757434f023c`

A6_disscussion_api_2 performs no authentication check whatsoever before accepting a POST body and writing the 'code' field verbatim to playground/A6/utility.py. Any unauthenticated caller can overwrite that Python module with arbitrary content.

**Evidence (citations):**

- `introduction/apis.py:126` - resolved
  > `def A6_disscussion_api_2(request):`
- `introduction/apis.py:130` - resolved
  > `code = request.POST.get('code')`
- `introduction/apis.py:133` - resolved
  > `f = open(filename,"w")`
- `introduction/apis.py:134` - resolved
  > `f.write(code)`

---

## 20. MD5 used for password hashing in authentication path  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-327  |  **Rule:** `codeguard-py-weak-crypto`

- **Location:** `introduction/mitre.py` - `csrf_lab_login` (line 159)
- **Fingerprint:** `fp_b69abfcd12429bd6`

The user-supplied password is hashed with MD5 before being compared to the stored value. MD5 is cryptographically broken, has no salt, and is trivially reversed with rainbow tables, making credential compromise straightforward.

**Evidence (citations):**

- `introduction/mitre.py:159` - resolved
  > `password = request.POST.get('password')`
- `introduction/mitre.py:161` - resolved
  > `password = md5(password.encode()).hexdigest()`
- `introduction/mitre.py:162` - resolved
  > `User = CSRF_user_tbl.objects.filter(username=username, password=password)`

---

## 21. Hardcoded JWT signing secret in csrf_lab_login  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/mitre.py` - `csrf_lab_login` (line 169)
- **Fingerprint:** `fp_20351de87381b0bb`

The JWT is signed with the string literal 'csrf_vulneribility' appearing directly in source code. Any attacker with read access to the codebase can forge valid JWT tokens, completely bypassing session authentication.

**Evidence (citations):**

- `introduction/mitre.py:169` - resolved
  > `cookie = jwt.encode(payload, 'csrf_vulneribility', algorithm='HS256')`

---

## 22. Hardcoded JWT verification secret in csrf_transfer_monei  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/mitre.py` - `csrf_transfer_monei` (line 182)
- **Fingerprint:** `fp_f6e1e8d5a60fdf8d`

jwt.decode is called with the same hardcoded secret 'csrf_vulneribility'. An attacker who knows this constant (or reads the source) can craft arbitrary JWT payloads that will be accepted as legitimate, bypassing the authentication check entirely.

**Evidence (citations):**

- `introduction/mitre.py:182` - resolved
  > `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'])`

---

## 23. Hardcoded JWT verification secret in csrf_transfer_monei_api  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/mitre.py` - `csrf_transfer_monei_api` (line 194)
- **Fingerprint:** `fp_7f9af2f39d5c4305`

The financial transfer endpoint verifies the JWT with the hardcoded literal 'csrf_vulneribility'. Combined with line 204's balance mutation, an attacker can forge tokens and perform unauthorized transfers.

**Evidence (citations):**

- `introduction/mitre.py:194` - resolved
  > `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'])`
- `introduction/mitre.py:204` - resolved
  > `recipent.balance = recipent.balance + int(amount)`

---

## 24. Helper executes arbitrary shell command with shell=True  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `introduction/mitre.py` - `command_out` (line 233)
- **Fingerprint:** `fp_2a867ca3879174fc`

command_out unconditionally passes its argument to subprocess.Popen with shell=True. The function has no input validation, allowlist, or argument-list form. Any caller that feeds external input into this function (as mitre_lab_17_api does at line 242) produces OS command injection.

**Evidence (citations):**

- `introduction/mitre.py:233` - resolved
  > `process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)`

---

## 25. Path traversal in ssrf_lab via caller-supplied 'file' parameter  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `introduction/playground/ssrf/main.py` - `ssrf_lab` (line 4)
- **Fingerprint:** `fp_8318b73ef828d274`

The 'file' parameter received by ssrf_lab is joined to the module directory with os.path.join without any realpath normalization or containment check. An attacker-supplied value such as '../../settings.py' would resolve outside the intended directory and expose arbitrary file contents.

**Evidence (citations):**

- `introduction/playground/ssrf/main.py:4` - resolved
  > `def ssrf_lab(file):`
- `introduction/playground/ssrf/main.py:7` - resolved
  > `filename = os.path.join(dirname, file)`
- `introduction/playground/ssrf/main.py:8` - resolved
  > `file = open(filename,"r")`

---

## 26. Full SQL query including user-controlled values returned to client on error  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-209  |  **Rule:** `codeguard-py-error-info-leak`

- **Location:** `introduction/views.py` - `sql_lab` (line 158)
- **Fingerprint:** `fp_95c7cbe66934bbf2`

On both the exception path and the wrong-password path, the template context includes 'sql_error' set to the raw sql_query string, which contains the user-supplied 'name' and 'password' values embedded in SQL syntax. This leaks internal database schema details and confirms injectable input positions to an attacker. The leaked value is a full SQL query, not a generic validation message.

**Evidence (citations):**

- `introduction/views.py:158` - resolved
  > `sql_query = "SELECT * FROM introduction_login WHERE user='"+name+"' AND password='"+password+"'"`
- `introduction/views.py:170` - resolved
  > `"sql_error":sql_query`
- `introduction/views.py:182` - resolved
  > `"sql_error":sql_query`

---

## 27. Missing authentication on XXE-vulnerable XML endpoint  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/views.py` - `xxe_parse` (line 256)
- **Fingerprint:** `fp_7de0c25b539df12d`

The xxe_parse handler processes arbitrary XML from request.body and writes extracted content to the database with no authentication check anywhere in the function. There is no is_authenticated guard, making this endpoint reachable by unauthenticated attackers who can also exploit the external entity expansion enabled by feature_external_ges.

**Evidence (citations):**

- `introduction/views.py:256` - resolved
  > `def xxe_parse(request):`
- `introduction/views.py:259` - resolved
  > `parser.setFeature(feature_external_ges, True)`
- `introduction/views.py:268` - resolved
  > `p=comments.objects.filter(id=1).update(comment=text)`

---

## 28. Unsafe YAML deserialization with full yaml.Loader on uploaded file  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-502  |  **Rule:** `codeguard-py-unsafe-deserialization`

- **Location:** `introduction/views.py` - `a9_lab` (line 558)
- **Fingerprint:** `fp_f4bc240ea7584248`

yaml.load() is called with yaml.Loader (the unrestricted loader) rather than yaml.SafeLoader on an attacker-supplied uploaded file. This allows arbitrary Python object instantiation, which can be exploited for remote code execution via crafted YAML.

**Evidence (citations):**

- `introduction/views.py:558` - resolved
  > `file=request.FILES["file"]`
- `introduction/views.py:560` - resolved
  > `data = yaml.load(file,yaml.Loader)`

---

## 29. Missing authorization: any authenticated user can access admin secret page  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/views.py` - `a1_broken_access_lab3_secret` (line 838)
- **Fingerprint:** `fp_df48e073307df12a`

The handler checks only is_authenticated but performs no role or privilege check before rendering the secret page. The in-code comment explicitly acknowledges this omission. Any authenticated user can reach this endpoint.

**Evidence (citations):**

- `introduction/views.py:838` - resolved
  > `if not request.user.is_authenticated:`
- `introduction/views.py:840` - resolved
  > `# no checking applied here`
- `introduction/views.py:841` - resolved
  > `return render(request, 'Lab_2021/A1_BrokenAccessControl/secret.html')`

---

## 30. Path traversal via unsanitized POST field used in os.path.join + open()  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `introduction/views.py` - `ssrf_lab` (line 923)
- **Fingerprint:** `fp_f82e4684c8dcceaf`

The `blog` POST field is joined with the server module's directory using `os.path.join` and then opened directly with `open()`. There is no `realpath`/`resolve` call or `commonpath` containment check, so a value like `../../etc/passwd` will resolve to an arbitrary absolute path and be read back to the user.

**Evidence (citations):**

- `introduction/views.py:923` - resolved
  > `file=request.POST["blog"]`
- `introduction/views.py:925` - resolved
  > `dirname = os.path.dirname(__file__)`
- `introduction/views.py:926` - resolved
  > `filename = os.path.join(dirname, file)`
- `introduction/views.py:927` - resolved
  > `file = open(filename,"r")`

---

## 31. SSRF via unsanitized user-controlled URL passed to requests.get()  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-918  |  **Rule:** `codeguard-py-ssrf`

- **Location:** `introduction/views.py` - `ssrf_lab2` (line 961)
- **Fingerprint:** `fp_529991d5861cbc7b`

The `url` POST field is passed without any validation directly to `requests.get()`. There is no scheme restriction, domain allowlist, or private/loopback IP filter, allowing an attacker to direct the server to make arbitrary HTTP requests to internal services.

**Evidence (citations):**

- `introduction/views.py:961` - resolved
  > `url = request.POST["url"]`
- `introduction/views.py:963` - resolved
  > `response = requests.get(url)`

---

## 32. Path traversal via blog_id URL parameter used directly as template path  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `introduction/views.py` - `ssti_lab` (line 1003)
- **Fingerprint:** `fp_2e8effe4cedc6482`

The blog_id argument is taken directly from the URL and interpolated unsanitized into the template path string passed to render(). An attacker can supply a traversal sequence such as '../../../settings' to cause Django to render arbitrary template-accessible files.

**Evidence (citations):**

- `introduction/views.py:1003` - resolved
  > `def ssti_view_blog(request,blog_id):`
- `introduction/views.py:1006` - resolved
  > `return render(request,f"Lab_2021/A3_Injection/Blogs/{blog_id}.html")`

---

## 33. MD5 used for password hashing — cryptographically broken  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-327  |  **Rule:** `codeguard-py-weak-crypto`

- **Location:** `introduction/views.py` - `crypto_failure_lab` (line 1026)
- **Fingerprint:** `fp_153f0436e465382e`

MD5 is applied directly to the user-supplied password before database lookup. MD5 is a banned hash algorithm under the workspace cryptographic policy: it is fast, reversible via rainbow tables, and unsuitable for password storage. A secure password hashing function (e.g., bcrypt, Argon2, PBKDF2) must be used instead.

**Evidence (citations):**

- `introduction/views.py:1026` - resolved
  > `password = md5(password.encode()).hexdigest()`
- `introduction/views.py:1027` - resolved
  > `user = CF_user.objects.filter(username=username,password=password).first()`

---

## 34. Plaintext password written to log via info-level log message  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-312  |  **Rule:** `codeguard-py-sensitive-data-exposure`

- **Location:** `introduction/playground/A9/api.py` - `log_function_target` (line 15)
- **Fingerprint:** `fp_a245c3bd049690b1`

Line 16 interpolates the raw password from the POST request body into an info-level log message. Any log aggregation system, file, or observer with log access will see cleartext credentials, violating basic secret hygiene.

**Evidence (citations):**

- `introduction/playground/A9/api.py:15` - resolved
  > `password = request.POST['password']`
- `introduction/playground/A9/api.py:16` - resolved
  > `L.info(f"POST request with username {username} and password {password}")`

---

## 35. Plaintext password written to log in archive.py — same defect as api.py  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-312  |  **Rule:** `codeguard-py-sensitive-data-exposure`

- **Location:** `introduction/playground/A9/archive.py` - `log_function_target` (line 15)
- **Fingerprint:** `fp_de6df0e22c044475`

The archive copy of log_function_target is identical to api.py: line 16 interpolates the raw POST password into an info-level log message, leaking credentials to any log consumer.

**Evidence (citations):**

- `introduction/playground/A9/archive.py:15` - resolved
  > `password = request.POST['password']`
- `introduction/playground/A9/archive.py:16` - resolved
  > `L.info(f"POST request with username {username} and password {password}")`

---

## 36. Hardcoded secret key returned in HTTP response  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `insec_des_lab` (line 216)
- **Fingerprint:** `fp_cf8ecd748cbb3f7e`

The string literal 'SECRETKEY:ADMIN123' is hardcoded directly in the source and returned to the client in the render context. It is not read from an environment variable or secrets manager, and is not a placeholder value.

**Evidence (citations):**

- `introduction/views.py:216` - resolved
  > `response = render(request,'Lab/insec_des/insec_des_lab.html', {"message":"Welcome Admin, SECRETKEY:ADMIN123"})`

---

## 37. Hardcoded secret value in source code  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `secret` (line 538)
- **Fingerprint:** `fp_08e98ddfdddf0ad7`

The string literal "S3CR37K3Y" is embedded directly in source code and returned as a secret to matching requests. Even in a lab context this is a clear CWE-798 instance: the value is a non-empty, non-placeholder literal hardcoded rather than loaded from an environment variable or secrets manager.

**Evidence (citations):**

- `introduction/views.py:538` - resolved
  > `return render(request,"Lab/sec_mis/sec_mis_lab.html", {"secret": "S3CR37K3Y"})`

---

## 38. Hardcoded plaintext credentials used for authentication  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `a1_broken_access_lab_1` (line 766)
- **Fingerprint:** `fp_13227cecd44ceffd`

The username `jack` and password `jacktheripper` are hardcoded as string literals and used directly in an authentication branch. These credentials are not read from environment variables, a secrets manager, or a runtime-injected config, and the inline comment confirms they were never rotated to hashed form.

**Evidence (citations):**

- `introduction/views.py:766` - resolved
  > `elif (name=='jack' and password=='jacktheripper'): # Will implement hashing here`

---

## 39. Hardcoded plaintext credentials used for authentication  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `a1_broken_access_lab_2` (line 789)
- **Fingerprint:** `fp_caaf6f79c06aca30`

Identical hardcoded credentials (`jack`/`jacktheripper`) appear again in `a1_broken_access_lab_2`, compared against POST-supplied `name` and `password` with no hashing or external secret lookup. Any source-code reader can impersonate this account.

**Evidence (citations):**

- `introduction/views.py:789` - resolved
  > `name = request.POST.get('name')`
- `introduction/views.py:790` - resolved
  > `password = request.POST.get('pass')`
- `introduction/views.py:806` - resolved
  > `elif ( name=='jack' and password=='jacktheripper'): # Will implement hashing here`

---

## 40. Hardcoded plaintext credentials for both user and admin accounts  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `a1_broken_access_lab_3` (line 831)
- **Fingerprint:** `fp_d4438b154c9bfa50`

Two sets of credentials (`John`/`reaper` and `admin`/`admin_pass`) are hardcoded as string literals and used in direct equality comparisons against user-supplied input. Neither is sourced from a secrets manager or environment variable, making both accounts trivially compromisable from source inspection.

**Evidence (citations):**

- `introduction/views.py:831` - resolved
  > `if username == 'John' and password == 'reaper':`
- `introduction/views.py:833` - resolved
  > `elif username == 'admin' and password == 'admin_pass':`

---

## 41. SQL query structure leaked to client on error  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-209  |  **Rule:** `codeguard-py-error-info-leak`

- **Location:** `introduction/views.py` - `injection_sql_lab` (line 864)
- **Fingerprint:** `fp_099806186aa50557`

On failure, the full constructed SQL query string is returned to the client in the response context under the key 'sql_error'. This reveals the exact query structure including any injected input, aiding an attacker in refining SQL injection payloads.

**Evidence (citations):**

- `introduction/views.py:864` - resolved
  > `sql_query = "SELECT * FROM introduction_sql_lab_table WHERE id='"+name+"'AND password='"+password+"'"`
- `introduction/views.py:888` - resolved
  > `"sql_error":sql_query`

---

## 42. Hardcoded secret value in response context  
**Verdict:** `true-positive`  |  **Severity:** `low`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `ba_lab` (line 352)
- **Fingerprint:** `fp_c872018e45e0f6d4`

The value '0NLY_F0R_4DM1N5' is a hardcoded string literal used as a secret/flag in the response data. It is not retrieved from an environment variable or secrets manager and is not a placeholder.

**Evidence (citations):**

- `introduction/views.py:352` - resolved
  > `"data":"0NLY_F0R_4DM1N5",`

---

## 43. Weak authentication — hardcoded JWT secret allows token forgery for financial operation  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-862  |  **Rule:** `codeguard-py-missing-authz`

- **Location:** `introduction/mitre.py` - `csrf_transfer_monei_api` (line 193)
- **Fingerprint:** `fp_e744f8a4a6ccaa7b`

The endpoint does perform a JWT decode as its auth gate, so CWE-862 (completely missing auth) is not strictly satisfied. However, the known-hardcoded secret 'csrf_vulneribility' (already flagged in candidates 7 and 9) means a determined attacker can forge the cookie and perform arbitrary money transfers. Full exploitability depends on confirming the hardcoded secret is the only protection.

**Evidence (citations):**

- `introduction/mitre.py:193` - resolved
  > `cookie = request.COOKIES['auth_cookiee']`
- `introduction/mitre.py:194` - resolved
  > `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'])`
- `introduction/mitre.py:204` - resolved
  > `recipent.balance = recipent.balance + int(amount)`

---

## 44. Potential argument injection via stored container_id in docker stop command  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `challenge/views.py` - `DoItFast.delete` (line 80)
- **Fingerprint:** `fp_3c784dab67d8bb55`

The `container_id` on line 80 originates from docker stdout captured in the POST handler, decoded and stripped, then persisted in the database. Docker container IDs are canonically 64-character hex strings and would not ordinarily contain spaces or shell tokens; however, if the upstream docker_image argument injection (candidate 0) is exploitable, a crafted docker run response could produce a container_id that injects arguments into the `docker stop` command via the same `command.split(" ")` pattern. Since `shell=False` holds here as well, classical OS command injection is not reachable, but the full attack path depends on whether container_id can be tampered in the DB or via upstream injection.

**Evidence (citations):**

- `challenge/views.py:80` - resolved
  > `command = f"docker stop {user_chal.container_id}"`
- `challenge/views.py:81` - resolved
  > `process = subprocess.Popen(command.split(" "), stdout=subprocess.PIPE)`

---

## 45. Potential template-path traversal via unsanitized blog_id URL parameter  
**Verdict:** `needs-review`  |  **Severity:** `medium`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `introduction/views.py` - `ssti_view_blog` (line 1003)
- **Fingerprint:** `fp_8eb212bb696691c4`

The URL-supplied `blog_id` is interpolated directly into a template path string passed to Django's `render()`. Django's built-in template loaders (`FileSystemLoader`, `AppDirectoriesLoader`) apply `safe_join` which rejects `../` components, but the actual exposure depends on the TEMPLATES configuration and whether any custom loader or `DIRS` entry is set up insecurely. Without visibility into the Django settings, a definitive exploitability determination cannot be made.

**Evidence (citations):**

- `introduction/views.py:1003` - resolved
  > `def ssti_view_blog(request,blog_id):`
- `introduction/views.py:1006` - resolved
  > `return render(request,f"Lab_2021/A3_Injection/Blogs/{blog_id}.html")`

---

## 46. No path traversal — destination paths are fully hardcoded  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `introduction/apis.py` - `log_function_checker` (line 67)
- **Fingerprint:** `fp_8019bc9604150ac4`

Both file paths are constructed from a fixed string literal joined to __file__'s directory. Neither log_code nor api_code is used as a path segment; they are only written as file content. The trigger condition for CWE-22 requires 'a path segment is, or derives from, external input', which is not the case here.

**Evidence (citations):**

- `introduction/apis.py:67` - resolved
  > `log_filename = os.path.join(dirname, "playground/A9/main.py")`
- `introduction/apis.py:68` - resolved
  > `api_filename = os.path.join(dirname, "playground/A9/api.py")`

---

## 47. Path traversal rule does not apply — write destination is a hardcoded path  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `introduction/utility.py` - `ssrf_code_converter` (line 34)
- **Fingerprint:** `fp_dce6e2b9162f8cc5`

The path traversal rule requires a path segment derived from external input. In ssrf_code_converter the output path is a fixed literal: 'playground/ssrf/main.py'. No user-supplied path segment influences where the file is written. The real risk is code injection into that file, which is a separate weakness class not covered by this path-traversal rule.

**Evidence (citations):**

- `introduction/utility.py:34` - resolved
  > `filename = os.path.join(dirname, "playground/ssrf/main.py")`

---
