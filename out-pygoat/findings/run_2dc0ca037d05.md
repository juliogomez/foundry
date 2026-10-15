# Foundry PoC - security findings report

- **Run:** `run_2dc0ca037d05`
- **Target:** `pygoat` @ `master`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 128  |  **Candidates:** 28  |  **Tokens:** 295189/2000000
- **Stop reason:** coverage-complete (all 128 units); trailing true-positive yield=0.92

## Summary

| Verdict | Count |
|---|---|
| true-positive | 23 |
| needs-review | 2 |
| false-positive | 3 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Unsandboxed eval() on user-supplied POST parameter  
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

## 2. OS command injection via unsanitized POST 'ip' in nmap command  
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

## 3. SQL injection via string concatenation of name and password into raw query  
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

## 4. Unsafe pickle deserialization of attacker-controlled cookie  
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

## 5. OS command injection via domain POST parameter in shell command  
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

## 6. Unsandboxed eval() on user-supplied POST parameter 'val'  
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

## 7. Code injection via user-supplied expression in ImageMath.eval()  
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

## 8. SQL Injection via unsanitized POST parameters in raw query  
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

## 9. Unauthenticated write to server-side Python source files  
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

## 10. Unauthenticated overwrite of server-side Python source file  
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

## 11. MD5 used for password hashing in authentication path  
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

## 12. Hardcoded JWT signing secret in csrf_lab_login  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/mitre.py` - `csrf_lab_login` (line 169)
- **Fingerprint:** `fp_20351de87381b0bb`

The JWT is signed with the string literal 'csrf_vulneribility' appearing directly in source code. Any attacker with read access to the codebase can forge valid JWT tokens, completely bypassing session authentication.

**Evidence (citations):**

- `introduction/mitre.py:169` - resolved
  > `cookie = jwt.encode(payload, 'csrf_vulneribility', algorithm='HS256')`

---

## 13. Hardcoded JWT verification secret in csrf_transfer_monei  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/mitre.py` - `csrf_transfer_monei` (line 182)
- **Fingerprint:** `fp_f6e1e8d5a60fdf8d`

jwt.decode is called with the same hardcoded secret 'csrf_vulneribility'. An attacker who knows this constant (or reads the source) can craft arbitrary JWT payloads that will be accepted as legitimate, bypassing the authentication check entirely.

**Evidence (citations):**

- `introduction/mitre.py:182` - resolved
  > `payload = jwt.decode(cookie, 'csrf_vulneribility', algorithms=['HS256'])`

---

## 14. Hardcoded JWT verification secret in csrf_transfer_monei_api  
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

## 15. Helper executes arbitrary shell command with shell=True  
**Verdict:** `true-positive`  |  **Severity:** `high`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `introduction/mitre.py` - `command_out` (line 233)
- **Fingerprint:** `fp_2a867ca3879174fc`

command_out unconditionally passes its argument to subprocess.Popen with shell=True. The function has no input validation, allowlist, or argument-list form. Any caller that feeds external input into this function (as mitre_lab_17_api does at line 242) produces OS command injection.

**Evidence (citations):**

- `introduction/mitre.py:233` - resolved
  > `process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)`

---

## 16. Unsafe YAML deserialization with full yaml.Loader on uploaded file  
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

## 17. Path traversal via unsanitized POST field used in os.path.join + open()  
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

## 18. SSRF via unsanitized user-controlled URL passed to requests.get()  
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

## 19. MD5 used for password hashing — cryptographically broken  
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

## 20. Hardcoded secret value in source code  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `secret` (line 538)
- **Fingerprint:** `fp_08e98ddfdddf0ad7`

The string literal "S3CR37K3Y" is embedded directly in source code and returned as a secret to matching requests. Even in a lab context this is a clear CWE-798 instance: the value is a non-empty, non-placeholder literal hardcoded rather than loaded from an environment variable or secrets manager.

**Evidence (citations):**

- `introduction/views.py:538` - resolved
  > `return render(request,"Lab/sec_mis/sec_mis_lab.html", {"secret": "S3CR37K3Y"})`

---

## 21. Hardcoded plaintext credentials used for authentication  
**Verdict:** `true-positive`  |  **Severity:** `medium`  |  **Class:** CWE-798  |  **Rule:** `codeguard-py-hardcoded-secret`

- **Location:** `introduction/views.py` - `a1_broken_access_lab_1` (line 766)
- **Fingerprint:** `fp_13227cecd44ceffd`

The username `jack` and password `jacktheripper` are hardcoded as string literals and used directly in an authentication branch. These credentials are not read from environment variables, a secrets manager, or a runtime-injected config, and the inline comment confirms they were never rotated to hashed form.

**Evidence (citations):**

- `introduction/views.py:766` - resolved
  > `elif (name=='jack' and password=='jacktheripper'): # Will implement hashing here`

---

## 22. Hardcoded plaintext credentials used for authentication  
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

## 23. Hardcoded plaintext credentials for both user and admin accounts  
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

## 24. Weak authentication — hardcoded JWT secret allows token forgery for financial operation  
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

## 25. Potential template-path traversal via unsanitized blog_id URL parameter  
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

## 26. Misclassified as CWE-78 — actual risk is CWE-94 / arbitrary file write  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `introduction/apis.py` - `log_function_checker` (line 64)
- **Fingerprint:** `fp_789a67201f2de4e2`

No OS shell command is constructed or executed from user input in this unit. The attacker-controlled content is written to a Python source file via f.write(), which is a file-write/code-injection pattern (CWE-434/CWE-94), not OS command injection (CWE-78). The CWE-78 trigger condition ('the command argument is reachable from a request handler argument') is not satisfied.

**Evidence (citations):**

- `introduction/apis.py:64` - resolved
  > `log_code = request.POST.get('log_code')`
- `introduction/apis.py:69` - resolved
  > `f = open(log_filename,"w")`
- `introduction/apis.py:70` - resolved
  > `f.write(log_code)`

---

## 27. No path traversal — destination paths are fully hardcoded  
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

## 28. Misclassified as CWE-78 — actual risk is CWE-94 / arbitrary file write  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-78  |  **Rule:** `codeguard-py-shell-injection`

- **Location:** `introduction/apis.py` - `A6_disscussion_api_2` (line 130)
- **Fingerprint:** `fp_b4afb89b11ef7fab`

No OS shell command is formed from user input; the POST parameter 'code' is written to a file via f.write(). This is an arbitrary-file-write / code-injection pattern (CWE-434/CWE-94), not OS command injection. The CWE-78 trigger condition requiring a shell command constructed from external input is not met.

**Evidence (citations):**

- `introduction/apis.py:130` - resolved
  > `code = request.POST.get('code')`
- `introduction/apis.py:134` - resolved
  > `f.write(code)`

---
