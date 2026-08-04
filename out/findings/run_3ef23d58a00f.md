# Foundry PoC - security findings report

- **Run:** `run_3ef23d58a00f`
- **Target:** `langflow` @ `1.7.3`
- **Model:** `claude-sonnet-4-6`  |  **Backend:** `cursor`
- **Units analyzed:** 5  |  **Candidates:** 0  |  **Tokens:** 3016/6000000
- **Stop reason:** coverage-complete (all 5 units); trailing true-positive yield=0.00

## Summary

| Verdict | Count |
|---|---|
| true-positive | 0 |
| needs-review | 0 |
| false-positive | 0 |

The findings are ordered by verdict and then severity. Every `true-positive` passed the evidence gate (all its citations resolve to real lines). The `needs-review` items depend of data flow outside the unit, or they had one or more citations that did not resolve.
