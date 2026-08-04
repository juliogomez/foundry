# Localizer: Antares + Foundry Integration

This optional advanced section describes how to use
[Cisco Antares](https://github.com/jgomez2/antares) as a **scope-reduction step**
before running the Foundry pipeline. It is additive: the existing guided path
(steps 1-7 in the README) remains unchanged and fully functional without Antares.

## The idea

**Antares finds WHERE (cheap, fast, local). Foundry proves WHAT (governed, verified, auditable).**

When a security advisory drops:

1. You give Antares a CWE (e.g. `CWE-22` for path traversal).
2. Antares uses a local 1B-parameter model to iteratively search the repository
   and produce a ranked shortlist of likely-vulnerable files, in about 30 seconds.
3. The localizer expands that shortlist to neighboring files (same directories)
   to mitigate Antares's noise.
4. Foundry runs its governed pipeline (Indexer → Detector → Triager → Reporter)
   only on that narrowed scope instead of the full codebase.

The result: verified, evidence-backed findings focused on the advisory, at a
fraction of the token cost and wall-clock time of a full-scope run.

## When to use localize vs. run

| Scenario | Command | What happens |
|---|---|---|
| Broad security posture (no specific advisory) | `python -m foundry_poc.cli run` | Full scope, all rules |
| Advisory-driven (e.g. "evaluate for CWE-22") | `python -m foundry_poc.cli localize --cwe CWE-22` | Antares narrows, Foundry deep-dives |

## Prerequisites

Everything from the main WALKTHROUGH, plus:

1. **Clone the Antares repo** as a sibling:
   ```
   git clone https://github.com/juliogomez/antares.git
   ```

2. **Install the Antares CLI** (editable, so it picks up updates):
   ```
   pip install -e ./antares/explore/antares-cli
   antares --version    # verify
   ```

3. **Start the mlx-lm server** (local Apple Silicon inference):
   ```
   cd antares && ./scripts/serve.sh antares
   ```
   The server runs on `http://127.0.0.1:8080`. The `localize` command checks for
   it automatically and will attempt to start it if you pass `--antares-repo`.

4. **`CURSOR_API_KEY` set** (same as for any Foundry run).

5. **Target fetched** (`bash scripts/fetch_target.sh`, same as the main walkthrough).

## Usage

### Basic localized run

```bash
python -m foundry_poc.cli localize --cwe CWE-22
```

This:
- Calls `antares query targets/langflow --cwe CWE-22 --format json --no-report`
- Parses the returned file list
- Expands scope using the `directory` strategy (default)
- Runs the full Foundry pipeline on the narrowed scope

### Expansion strategies

Control how broadly the localizer expands Antares's picks:

```bash
# Only the exact files Antares returned
python -m foundry_poc.cli localize --cwe CWE-22 --expand exact

# All .py files in the same directories (default, recommended)
python -m foundry_poc.cli localize --cwe CWE-22 --expand directory

# Same as directory + sibling directories one level up
python -m foundry_poc.cli localize --cwe CWE-22 --expand parent

# Ignore Antares, scan everything (equivalent to `run`, useful as baseline)
python -m foundry_poc.cli localize --cwe CWE-22 --expand full
```

### With auto-starting the server

```bash
python -m foundry_poc.cli localize --cwe CWE-22 --antares-repo ./antares
```

If the mlx-lm server is not responding, the localizer will attempt to start it
via `antares/scripts/serve.sh`.

### Using the example config

A dedicated config is provided for localized runs with a lower token budget:

```bash
python -m foundry_poc.cli localize --config config-localize-example.yaml --cwe CWE-22
```

## How scope expansion works

Antares has ~33% hit@any on its benchmark (the right file appears in the list
about 1/3 of the time). Using Antares as an exclusive filter would cap recall.

The localizer mitigates this with **neighborhood expansion**: when Antares returns
files like `src/api/v1/flows.py` and `src/api/v1/auth.py`, the `directory`
strategy collects their directories (`src/api/v1/`) and expands to all Python
files there.

Why this works:
- Antares correctly identifies the right *module/area* even when it misses the exact file.
- Vulnerabilities cluster within modules.
- Still much narrower than a full-repo scan (289 units → ~30–60 units).

## Expected savings

On Langflow with CWE-22 (path traversal):

| | Full scope (`run`) | Localized (`localize --cwe CWE-22`) |
|---|---|---|
| **Units analyzed** | 289 | ~30–60 (depends on expansion) |
| **Token cost** | ~2M | ~200–600K |
| **Time** | ~15 min | ~5 min (Antares ~30s + smaller Foundry run) |
| **Use case** | Broad security posture | Targeted advisory response |

Both modes remain available. The operator picks based on the situation.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│  python -m foundry_poc.cli localize --cwe CWE-22     │
└──────────────┬───────────────────────────────────────┘
               │
       ┌───────▼────────┐
       │  localizer.py  │
       │  check prereqs │
       └───────┬────────┘
               │
       ┌───────▼─────────────────────┐
       │  antares query <target>     │
       │  --cwe CWE-22 --format json │
       │  (local mlx-lm, ~30s)       │
       └───────┬─────────────────────┘
               │ JSON: [{file_path, submission_rank, ...}]
       ┌───────▼────────────────┐
       │  expand_scope()        │
       │  directory -> globs    │
       └───────┬────────────────┘
               │ include_globs
       ┌───────▼────────────────────────────────────┐
       │  Foundry pipeline (same as `run`)          │
       │  Indexer -> Detector -> Triager -> Reporter│
       │  (Cursor SDK / Claude Sonnet, governed)    │
       └────────────────────────────────────────────┘
```

## Module reference

### `foundry_poc/localizer.py`

| Function | Purpose |
|---|---|
| `check_antares_cli()` | Verify `antares` is on PATH |
| `check_server(endpoint)` | Verify the mlx-lm server responds |
| `attempt_start_server(antares_repo)` | Auto-start via `serve.sh` |
| `run_antares_cli(repo, cwe, ...)` | Shell out to `antares query`, return parsed JSON |
| `extract_files(antares_result)` | Pull ranked file paths from the result |
| `expand_scope(files, target, strategy)` | Generate Foundry-compatible `include_globs` |
| `generate_localized_config(base_raw, scope_globs, cwe)` | Patch config with narrowed scope |
| `localize_and_run(...)` | End-to-end orchestrator |

## Relationship to the Antares repo

This integration uses the **official Antares CLI** (`antares query`), not
`minimal_agent.py` or `run_eval.py`. Those are for benchmarking and learning;
the CLI is for product workflows with structured JSON/SARIF output.

The Antares repo documents this distinction in
[docs/VALUE.md](https://github.com/jgomez2/antares/blob/main/docs/VALUE.md#why-not-ciscos-official-cli-for-benchmarking).
