# Foundry PoC - security findings report

- **Run:** `run_9d4f741a4b29`
- **Target:** `mlflow` @ `v2.9.0`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 70  |  **Candidates:** 2  |  **Tokens:** 448867/2000000
- **Stop reason:** coverage-complete (all 70 units); trailing true-positive yield=0.00

## Summary

| Verdict | Count |
|---|---|
| true-positive | 0 |
| needs-review | 1 |
| false-positive | 1 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.

## 1. Potential path traversal via flavor config parameters_path  
**Verdict:** `needs-review`  |  **Severity:** `high`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `mlflow/_promptlab.py` - `_load_pyfunc` (line 82)
- **Fingerprint:** `fp_20746c707bc3d406`

The `parameters_path` is constructed by joining the caller-supplied `path` with `pyfunc_flavor_conf["parameters_path"]`, a value read from the model's flavor configuration. If an attacker controls the model artifact (e.g., a malicious MLflow model), they could craft `parameters_path` to contain `../` sequences and escape the intended model directory. However, the exploitability depends on whether `path` and `pyfunc_flavor_conf` originate from a trusted source or can be influenced by an attacker, which is not fully determinable from the shown code alone.

**Evidence (citations):**

- `mlflow/_promptlab.py:82` - resolved
  > `pyfunc_flavor_conf = _get_flavor_configuration(model_path=path, flavor_name=pyfunc.FLAVOR_NAME)`
- `mlflow/_promptlab.py:83` - resolved
  > `parameters_path = os.path.join(path, pyfunc_flavor_conf["parameters_path"])`
- `mlflow/_promptlab.py:84` - resolved
  > `with open(parameters_path) as f:`

---

## 2. CLI filename argument write path is user-intentional  
**Verdict:** `false-positive`  |  **Severity:** `none`  |  **Class:** CWE-22  |  **Rule:** `codeguard-py-path-traversal`

- **Location:** `mlflow/experiments.py` - `generate_csv_with_runs` (line 129)
- **Fingerprint:** `fp_40529f00784ffa9d`

The `filename` argument is a CLI-supplied option passed directly to `runs.to_csv(filename, ...)`. In a CLI tool context, a user specifying an output file path is the intended and expected behavior — the user is writing to their own filesystem at a location of their choosing. There is no server-side or multi-tenant trust boundary being crossed; the caller and the file system actor are the same principal. This pattern does not constitute an exploitable CWE-22 because there is no unauthorized path escape across a trust boundary.

**Evidence (citations):**

- `mlflow/experiments.py:129` - resolved
  > `def generate_csv_with_runs(experiment_id, filename):`
- `mlflow/experiments.py:135` - resolved
  > `if filename:`
- `mlflow/experiments.py:136` - resolved
  > `runs.to_csv(filename, index=False)`

---
