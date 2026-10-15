# Foundry PoC - security findings report

- **Run:** `run_95a5816f18ab`
- **Target:** `langflow` @ `1.7.3`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 53  |  **Candidates:** 3  |  **Tokens:** 444444/2000000
- **Stop reason:** coverage-complete (all 53 units); trailing true-positive yield=0.00

## Summary

| Verdict | Count |
|---|---|
| true-positive | 0 |
| needs-review | 1 |
| false-positive | 2 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Unsanitized caller-supplied path passed directly to file write  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `src/lfx/src/lfx/services/settings/base.py` - `save_settings_to_yaml` (line 630)
- **Fingerprint:** `fp_474ffe674ce860af`

Line 631 passes `file_path` directly to `Path(file_path).open("w")` with no `resolve()`, no `os.path.commonpath` containment check, and no allow-list validation. A value such as `../../etc/cron.d/evil` would open and overwrite a file outside any intended directory. Whether this constitutes an exploitable CWE-22 depends on whether callers ever pass externally controlled input into this parameter; that data-flow is not visible in the shown lines. The complete absence of any path sanitization warrants manual review of all call sites.

**Evidence (citations):**

- `src/lfx/src/lfx/services/settings/base.py:630` - resolved
  > `def save_settings_to_yaml(settings: Settings, file_path: str) -> None:`
- `src/lfx/src/lfx/services/settings/base.py:631` - resolved
  > `with Path(file_path).open("w", encoding="utf-8") as f:`

---

## 2. Path traversal mitigated by .name stripping directory components  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `src/lfx/src/lfx/services/settings/base.py` - `load_settings_from_yaml` (line 643)
- **Fingerprint:** `fp_a5c779abd07ca5d5`

Line 645 opens the file using `file_path_.name`, which is the Path `.name` property that returns only the final filename component, stripping all directory segments including any `../` traversal sequences. Regardless of whether the else branch (line 643) constructs a path from an attacker-supplied value containing slashes, the traversal component is discarded before the open call. The code does not actually open the resolved `file_path_` but only its basename relative to the current working directory. While this is a logic bug (the constructed safe path is thrown away), it prevents the classic CWE-22 escape pattern because no directory traversal survives to the `async_open` call.

**Evidence (citations):**

- `src/lfx/src/lfx/services/settings/base.py:643` - resolved
  > `file_path_ = Path(file_path)`
- `src/lfx/src/lfx/services/settings/base.py:645` - resolved
  > `async with async_open(file_path_.name, encoding="utf-8") as f:`

---

## 3. yaml.safe_load is not a deserialization vulnerability  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-502  |  **Rule:** `codeguard-py-unsafe-deserialization`

- **Location:** `src/lfx/src/lfx/services/settings/base.py` - `load_settings_from_yaml` (line 647)
- **Fingerprint:** `fp_1b62572bb5831e83`

Line 647 uses `yaml.safe_load(content)`, which restricts YAML parsing to basic Python primitives and does not allow arbitrary object instantiation. The candidate itself acknowledges this is safe and explicitly states no separate deserialization issue exists beyond the path-traversal finding. CWE-502 requires unsafe deserialization of attacker-controlled data; `yaml.safe_load` is the standard safe mitigation for YAML deserialization and does not qualify.

**Evidence (citations):**

- `src/lfx/src/lfx/services/settings/base.py:647` - resolved
  > `settings_dict = yaml.safe_load(content)`

---
