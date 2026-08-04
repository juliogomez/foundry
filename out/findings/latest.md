# Foundry PoC - security findings report

- **Run:** `run_6edb0bb53a72`
- **Target:** `langflow` @ `1.7.3`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 289  |  **Candidates:** 1  |  **Tokens:** 149294/6000000
- **Stop reason:** coverage-complete (all 289 units); trailing true-positive yield=0.00

## Summary

| Verdict | Count |
|---|---|
| true-positive | 0 |
| needs-review | 1 |
| false-positive | 0 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Mock finding  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-94  |  **Rule:** `codeguard-py-code-injection-exec`

- **Location:** `src/backend/base/langflow/api/v1/voice_mode.py` - `FunctionCall._send_function_call._call` (line 44)
- **Fingerprint:** `fp_3312d6f7659915ca`

Mock triage rationale (offline stub).

**Evidence (citations):**

- `x:0` - UNRESOLVED - file not found in target: x

---
