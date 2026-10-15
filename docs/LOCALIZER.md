# Localizer: Antares + Foundry Integration

This optional advanced section describes how to use
[Antares](https://huggingface.co/collections/fdtn-ai/antares) as a **scope-reduction step**
before running the Foundry pipeline. It is additive: the existing guided path
(steps 1-7 in the README) remains unchanged and fully functional without Antares.

## The Antares repo

The localizer role continues my work on
[**Antares**](https://github.com/juliogomez/antares), a Cisco-originated project
that answers a narrow question cheaply: *given a CWE from a security advisory,
which files in this codebase are most likely affected?*

Antares runs a small local model (I'm running it via mlx-lm on my M1 MBP) and iteratively
searches the repository. A typical query finishes in under a minute (22–56s on
PyGoat) and returns a ranked shortlist of files suspected to be vulnerable. You
do not need cloud inference or a full-repo LLM sweep just to decide where to look.

That shortlist is what makes "foundry localize" practical. Foundry's governed
pipeline is thorough but token-heavy in terms of LLM usage; pointing it at only
the relevant part of the codebase (128 of 180 units on PyGoat) is how you respond
to a specific advisory without paying for a full posture run.
The Antares repo is where you get the CLI, the serve scripts, the benchmark
harness, and the docs for how localization works on its own. Clone it next to this
repo and install the CLI from there.

Models and weights live on
[Hugging Face](https://huggingface.co/collections/fdtn-ai/antares), the GitHub repo
is the code you run.

## The idea

**Antares finds WHERE (cheap, fast, local). Foundry proves WHAT (governed, verified, auditable).**

When a security advisory drops:

1. You give Antares a CWE (e.g. CWE-78 for shell injection).
2. Antares uses a locally run 1B-parameter model to iteratively search the repository
   and produce a ranked shortlist of likely-vulnerable files, in under a minute.
3. The localizer expands that shortlist to neighboring files (same directories)
   to mitigate Antares's noise.
4. Foundry runs its governed pipeline (Indexer → Detector → Triager → Reporter)
   only on that narrowed scope instead of the full codebase.

The result: verified, evidence-backed findings focused on the advisory, at
lower cost and faster than a full-scope run. Antares runs locally at zero cost
(no API calls, no token billing), and the narrowed scope means fewer Foundry
LLM calls. 30% fewer tokens for example on PyGoat, with larger savings on repos where
Antares can narrow to a smaller fraction of the codebase.

Antares only narrows *where* to look. Foundry then runs all of its rules on that
area, so a localized run reports the CWE you asked about plus any other weaknesses
in the same files. See [When to use each mode](#when-to-use-each-mode) for when
to pick _localize_ over _run_.

## Prerequisites

Everything from the main WALKTHROUGH.md doc, plus:

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

5. **Target fetched** (e.g. `bash scripts/fetch_target.sh pygoat` for the
   recommended demo, or `bash scripts/fetch_target.sh langflow` for the
   governance walkthrough).

## Usage

### Basic localized run (PyGoat)

PyGoat (OWASP) is the recommended demo target — a 1.1 MB Django web
application with 70+ Python files, small enough for Antares and containing
application-level vulnerability patterns that Foundry's rules detect.

```bash
bash scripts/fetch_target.sh pygoat
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78
```

This:
- Calls `antares query targets/pygoat --cwe CWE-78 --format json --no-report`
- Parses the returned file list (e.g. `introduction/mitre.py`)
- Expands scope using the `directory` strategy (default) → `introduction/*.py`
- Runs the full Foundry pipeline on the narrowed scope

### Expansion strategies

Control how broadly the localizer expands Antares's picks:

```bash
# Only the exact files Antares returned
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78 --expand exact

# All .py files in the same directories (default, recommended)
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78 --expand directory

# Same as directory + sibling directories one level up
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78 --expand parent

# Ignore Antares, scan everything (equivalent to `run`, useful as baseline)
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78 --expand full
```

### With auto-starting the server

```bash
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78 --antares-repo ./antares
```

If the mlx-lm server is not responding, the localizer will attempt to start it
via `antares/scripts/serve.sh`.

### Using a different target

You can use `localize` with any target config. For example, with the Langflow
localization template (note: Langflow at ~175 MB is beyond Antares's effective
range — see [Repository size constraint](#repository-size-constraint)):

```bash
python -m foundry_poc.cli localize --config config-localize-example.yaml --cwe CWE-22
```

## Repository size constraint

Antares's localization accuracy depends heavily on repository size. The [Antares
paper](https://arxiv.org/pdf/2608.02407) (Section 8.3,
Figure 6) quantifies this across 500 tasks on 290 real-world repositories:

| Repository size | Antares-3B F1 | Antares-1B F1 | Practical accuracy |
|---|---|---|---|
| **< 100 KB** | ~0.83 | ~0.84 | Excellent: the 15-turn budget covers most of the codebase |
| **100 KB – 500 KB** | Competitive | Strong | Good: grep-based elimination still effective |
| **0.5 – 2 MB** | Declining | Declining | Adequate with expansion strategies |
| **2 – 10 MB** | Significantly lower | Significantly lower | Marginal: consider `--expand parent` |
| **10+ MB** | Near floor | Near floor | **Not effective**: use `run` instead |

The underlying cause is structural: Antares uses a 1B-parameter model with a
15-command interaction budget. On small repos, grep-based elimination and
targeted file inspection can cover most of the codebase within that budget. As
repos grow past a few megabytes, the search space exceeds what the agent can
explore, and localization degrades to near-random file selection.

### What we observed

Our tests matched the paper:

- **Large repos failed.** On Langflow (~175 MB) and MLflow (~112 MB), Antares
  either hung or pointed at the wrong files, and the localized runs found 0
  true-positives.
- **Small library repos localized correctly.** On bottle, PyYAML and Werkzeug
  (all under 2 MB), Antares found the vulnerable module in under a minute, but
  Foundry reported nothing (see the next section for why).
- **A small application worked end to end.** On PyGoat (1.1 MB), Antares found
  the right file in 22 seconds and Foundry confirmed real vulnerabilities in
  that area.

The run tables are in
[RESULTS.md](RESULTS.md#antares-localization-repo-size-constraint-and-honest-assessment).

### Key insight: application code, not libraries

Antares localizes files; Foundry detects vulnerability patterns in code. For
the integration to produce findings, the target must be **application code**
that uses potentially unsafe APIs (e.g. calling `pickle.loads()`, `eval()`,
`subprocess` with `shell=True`, raw SQL queries). Library repos (bottle,
PyYAML, Werkzeug) implement these APIs. They are the library's purpose, not a
vulnerability pattern. Foundry's rules correctly do not flag library internals.

For the demo, this means using a web application like PyGoat (OWASP's
intentionally vulnerable Django app), not a library repo, even if the library
has known CVEs.

## How scope expansion works

Antares has ~33% hit@any on its benchmark (VLoc Bench, n=500 tasks): the right
file appears in its list about 1/3 of the time. That figure is a macro-average
across all repo sizes; it is substantially higher on repos under 500 KB and well
below average on repos over 10 MB. Using Antares as an exclusive filter would
cap recall.

The localizer mitigates this with **neighborhood expansion**: when Antares returns
a file like `introduction/mitre.py`, the `directory` strategy collects its
directory (`introduction/`) and expands to all Python files there.

Why this works:
- Antares correctly identifies the right *module/area* even when it misses the exact file.
- Vulnerabilities cluster within modules.
- Still narrower than a full-repo scan (180 → 128 units on PyGoat; much more on
  repos with deeper package structure).

## When to use each mode

The two modes answer different questions and are complementary, not interchangeable.
**Repository size is the primary decision factor for localization.**

| Scenario | Repo size | Command | What to expect |
|---|---|---|---|
| Advisory-driven, small repo | < 2 MB | `localize --cwe CWE-NNN` | Fast, accurate narrowing; best cost/value ratio |
| Advisory-driven, medium repo | 2–10 MB | `localize --cwe CWE-NNN --expand parent` | Workable with broader expansion to compensate |
| Advisory-driven, large repo | 10+ MB | `run` with scoped globs | Use full sweep; Antares cannot localize at this scale |
| Broad security posture (any size) | Any | `run` | Full scope, all rules; thorough but token-heavy |

- **Full scope (`run`)**: broad security posture across the entire target surface.
  Thorough but token-heavy. Works at any repo size.
- **Localized (`localize --cwe ...`)**: fast, cheaper, advisory-driven response.
  Antares narrows scope in seconds at zero cost (local model), and Foundry
  analyzes only the narrowed set: fewer LLM calls, fewer tokens. Effective on
  repos under ~2 MB, workable with `--expand parent` at 2–10 MB (based on the
  paper; none of our test repos falls in that range), and not effective above
  10 MB, where Antares's 15-turn budget cannot cover enough of the codebase.

Repo size only limits Antares's localization step. Foundry's detection, triage
and governance properties work the same at any size.

The right deployment is both: localized for speed when the advisory lands
(on an appropriately-sized target), full-scope for completeness when the budget
allows or when the target is too large for Antares.

**Demonstrated on PyGoat (1.1 MB):** the localized run used 30% fewer Foundry
tokens than the full run and surfaced 25 findings (23 true-positives) in the area
Antares pointed to, versus 45 across the whole app for the full run. See
[RESULTS.md](RESULTS.md#pygoat-antares--foundry-integration-demo-the-proof)
for the full comparison.

## Relationship to the Antares repo

This integration uses the **official Antares CLI** (`antares query`) from
[github.com/juliogomez/antares](https://github.com/juliogomez/antares), not
`minimal_agent.py` or `run_eval.py`. Those scripts are for benchmarking and
learning how the agent works; the CLI is what you want for product workflows
(structured JSON/SARIF output, stable flags, pip-installable).

The Antares repo documents this distinction in
[docs/VALUE.md](https://github.com/juliogomez/antares/blob/main/docs/VALUE.md#why-not-ciscos-official-cli-for-benchmarking).
If you want to understand hit rates, expansion trade-offs, or run the benchmark
yourself before trusting the localizer here, start there.
