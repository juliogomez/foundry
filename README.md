# Foundry Security Spec in the real world

This repo is a proof of concept. It implements the
[Foundry security harness specification](https://github.com/CiscoDevNet/foundry-security-spec)
and demonstrates it against multiple real targets:
[Langflow](https://github.com/langflow-ai/langflow) (governance thesis),
[MLflow](https://github.com/mlflow/mlflow) (scale validation), and
[PyGoat](https://github.com/adeyosemanputra/pygoat) (Antares integration demo).

## What Foundry is

Foundry is a **governance and repeatability layer over the model you already trust**.
It does not make the model smarter, it makes the output *verifiable, tiered,
auditable, bounded, repeatable, and self-improving*. The same model, wrapped in the
harness, produces findings a security program can build a process on. Without it, you
get an answer you have to trust on faith.

The full thesis and the evidence behind it: **[VALUE.md](docs/VALUE.md)**.

## The integrated security loop: Antares + Foundry + CodeGuard

Foundry is one part of a larger loop where three Cisco-originated projects each
address a different phase of the security lifecycle:

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                                                                     │
  │   ANTARES                FOUNDRY                 CODEGUARD          │
  │   Advisory → Scope       Detect + Triage         IDE Prevention     │
  │                                                                     │
  │   "Which files are       "Is it real? Is it      "Never write it    │
  │    likely affected?"      verified? Log it."      again, anywhere." │
  │                                                                     │
  │        │                      │                       │             │
  │        │  CWE + file list     │  rule-gaps.jsonl      │  fewer      │
  │        ▼                      ▼                       ▼  vulns      │
  │   ┌─────────┐           ┌──────────┐           ┌──────────┐         │
  │   │ Scope   │──────────▶│ Governed │──────────▶│ Prevent  │         │
  │   │ narrow  │           │ evaluate │           │ at the   │────┐    │
  │   └─────────┘           └──────────┘           │ keystroke│    │    │
  │                                                └──────────┘    │    │
  │                                                                │    │
  │        ◀───────────────────────────────────────────────────────┘    │
  │                     next run finds less                             │
  └─────────────────────────────────────────────────────────────────────┘
```

| Project | Role | Input | Output |
|---------|------|-------|--------|
| **[Antares](https://huggingface.co/collections/fdtn-ai/antares)** | Localize: identify which files are likely affected by a CWE | Security advisory | Ranked file shortlist |
| **[Foundry](https://github.com/CiscoDevNet/foundry-security-spec)** | Evaluate: governed detection, evidence-gated triage, deduplication | Code scope + rules | Verified findings + rule-gaps |
| **[CodeGuard](https://project-codeguard.org/)** | Prevent: embed rules into AI coding agents so the weakness cannot be reintroduced | Rule-gaps | Always-on IDE guardrails |

Each detection dollar spent once compounds into prevention everywhere, forever. The
`codeguard-*` rules governing *this very workspace* are the same format, the loop
is already in operation.

Deep dive: **[CODEGUARD.md](docs/CODEGUARD.md)** and **[LOCALIZER.md](docs/LOCALIZER.md)**.

## The demonstrations

**Governance thesis (Langflow).** The PoC evaluates the **entire Langflow v1 API
surface** (289 function-level units, 25 modules). Foundry surfaces roughly **2x the
confirmed findings** of a fair baseline agent (same model, same code, disciplined
prompt) at ~10x the token cost. Two runs collapse to the same distinct fingerprints
instead of producing two unrelated walls of text. The difference is not insight; it
is governance.

**Second codebase (MLflow).** To check that Foundry isn't tailored to Langflow, we
ran it on MLflow v2.9.0, a different and larger project (830 functions, about 3x
Langflow's 289). We only changed the config file to point to the new repo, but the engine code stayed the same. The evidence gate, the declared stop under the token cap, and the per-finding
audit trail all behaved the same way.

**Antares integration (PyGoat).** The end-to-end proof of Antares + Foundry
_localize_: Antares identifies the file affected by CWE-78 (shell injection) in
22 seconds at zero cost (local model). Foundry then runs all 13 rules on the
narrowed scope, finding 23 true-positives — including the targeted CWE-78 plus
adjacent weaknesses in the same area — using 30% fewer tokens than a full sweep.

**Prevention experiment (CodeGuard).** A blind A/B test of whether the rules change
what an AI agent writes. Across 72 agent sessions, the agent wrote the target
weakness 5 times out of 24 with no rules and 4 out of 24 with CodeGuard's core
rules, but **0 out of 24** with the rules Foundry synthesized added. See
[PREVENTION.md](docs/PREVENTION.md).

Numbers and methodology: **[RESULTS.md](docs/RESULTS.md)** and
**[METHODOLOGY.md](docs/METHODOLOGY.md)**.

## Documentation

| Doc | What it covers |
|-----|----------------|
| [VALUE.md](docs/VALUE.md) | The full governance thesis, the six properties, and the flywheel |
| [METHODOLOGY.md](docs/METHODOLOGY.md) | Experiment design, the fair baseline, pre-registered metrics |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | How Foundry roles map to the code |
| [CUSTOMIZATION.md](docs/CUSTOMIZATION.md) | How `config.yaml` and `rules/` are your customized spec |
| [WALKTHROUGH.md](docs/WALKTHROUGH.md) | Step-by-step run instructions |
| [RESULTS.md](docs/RESULTS.md) | Numbers from the real runs (Langflow, MLflow, PyGoat) |
| [BUILD-YOUR-OWN.md](docs/BUILD-YOUR-OWN.md) | Take it to your own repo |
| [LOCALIZER.md](docs/LOCALIZER.md) | Antares integration for advisory-driven scope |
| [CODEGUARD.md](docs/CODEGUARD.md) | CodeGuard integration for prevention-at-the-keystroke |
| [PREVENTION.md](docs/PREVENTION.md) | Controlled A/B test: do the synthesized rules change what an AI agent writes? |

## Quickstart

```bash
git clone https://github.com/juliogomez/foundry.git && cd foundry

python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Fetch targets (all, or specify one: langflow, mlflow, pygoat, etc.)
bash scripts/fetch_target.sh langflow

# Offline smoke test (no key, no spend)
FOUNDRY_LLM=mock python -m foundry_poc.cli run --limit 10

# Real run (uses your Cursor license)
export CURSOR_API_KEY=...
python -m foundry_poc.cli run
python -m foundry_poc.cli baseline
python -m foundry_poc.cli score --foundry out/foundry-<run>.json \
                                --baseline out/baseline-<run>.json

# Close the flywheel: generate CodeGuard prevention rules from detected gaps
python -m foundry_poc.cli synthesize

# Antares integration demo (requires Antares CLI + mlx-lm server)
bash scripts/fetch_target.sh pygoat
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78

# Prevention experiment: measure whether the rules change what an agent writes
bash scripts/fetch_codeguard.sh
python -m foundry_poc.cli prevention --reps 2
```

## What is inside the repo

| Path | What it is |
|------|------------|
| `foundry_poc/` | Implementation of the Foundry roles (Indexer, Detector, Triager, Reporter, Orchestrator) plus store, provenance, budget, and evidence gate. |
| `rules/` | CodeGuard detection rules (YAML patterns the LLM evaluates). |
| `config.yaml` | The customized spec for the wide Langflow run (289 units). See [CUSTOMIZATION.md](docs/CUSTOMIZATION.md). |
| `config-narrow.yaml` | A 12-module Langflow scale contrast (107 units). |
| `config-mlflow.yaml` | Full-scope MLflow v2.9.0 (830 units). |
| `config-pygoat.yaml` | PyGoat (OWASP) for the Antares integration demo (180 units). |
| `config-localize-example.yaml` | Antares-localized runs template. See [LOCALIZER.md](docs/LOCALIZER.md). |
| `scripts/fetch_target.sh` | Downloads evaluation targets at pinned revisions (Langflow, MLflow, PyGoat, and others). |
| `examples/synthesized/` | CodeGuard prevention rules generated by `synthesize` from the real Langflow and MLflow rule-gaps. |
| `experiments/prevention/` | Task set for the prevention experiment. See [PREVENTION.md](docs/PREVENTION.md). |
| `scripts/fetch_codeguard.sh` | Downloads and checksum-verifies the pinned Project CodeGuard release into `vendor/` (not committed). |
| `docs/` | All documentation (see table above). |
| `out/`, `out-mlflow/`, `out-pygoat/` | Generated artifacts: findings, provenance, rule-gaps, comparisons (per target). |
| `out-prevention/` | Prevention experiment artifacts: trials, generated code, blind judge inputs, judge run, results. |

## The backend

LLM calls go through the **Cursor SDK** using your Cursor plan. You
authenticate with a CURSOR_API_KEY from Cursor Dashboard. No secrets are written to
disk. Without a key, everything works in "FOUNDRY_LLM=mock" mode for offline
validation.

## A note about honesty

The baseline receives the same model with a disciplined prompt that asks for the same
rigor. I do not weaken it on purpose. Whatever the run produces is what the docs
report, including where the harness did not help. See
[METHODOLOGY.md](docs/METHODOLOGY.md).
