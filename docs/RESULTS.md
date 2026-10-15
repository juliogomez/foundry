# Results

These numbers come from real runs against multiple targets: Langflow 1.7.3
(governance thesis and baseline comparison), MLflow 2.9.0 (scale validation), and
PyGoat (Antares integration demo). Everything here can be reproduced from the
artifacts in `out/`, `out-mlflow/`, and `out-pygoat/`. The methodology for the
controlled Langflow experiment was defined in [METHODOLOGY.md](METHODOLOGY.md)
**before** the run.

The **canonical run is the wide scope**: the entire Langflow v1 API surface (289
function-level units across 25 modules) plus the compile()/exec() helper. A smaller
curated 12-module run (`config-narrow.yaml`, artifacts in `out-narrow/`) is kept as a
scale contrast and discussed at the end.

**A word on terms: which number counts which row.** A **finding** is
one candidate weakness the system recorded; each has a verdict. In the representative
run the funnel was: **61** candidates proposed -> **58** *stored* (after dedup)
-> of those, **32** *surfaced* (`confirmed` + `needs-review`, what a human reviews)
and **26** rejected (kept internal, never shown). The two headline comparisons read
**different rows**: **(a) vs. the baseline** uses the **surfaced** row (32); **(b)
against itself** uses the **stored** row (58 here, 64 in the other run), because dedup
tracks the whole store. So "surfaced 32" and "stored 64" are two rows of one funnel,
not a contradiction. We use "finding" throughout - never "issue".

With a strong model (like claude-sonnet-4-6) and a *fair, disciplined* baseline prompt, there are two separate comparisons.

**(a) Foundry vs. the baseline agent (one run, same model, same code):**

- **Citation quality ties.** Both arms resolve 100% of confirmed citations with
  zero hallucinations. We did not weaken the baseline to manufacture a gap.
- **Foundry surfaces ~2x more findings worth reviewing - 32 vs 15 - but not
  because the model is smarter.** *Here more is better*: a single agent turn curates
  a short headline list, while Foundry sweeps every one of the 289 units under a
  bounded budget. Completeness is a property of the **harness**, not the model.
- **Foundry costs ~10x more tokens (2.05M vs 213k).** It is *not* cheaper. The
  extra spend buys exhaustive coverage + the evidence gate + dedup, under a hard,
  declared cap.

**(b) Foundry against itself (the same pipeline run twice - only to *exhibit*
repeatability; on unchanged code the second run learns nothing new, it stands in for
the next CI run on the next commit):**

- **Across both runs the store held 122 finding-records, deduped to 67 distinct.**
  *Here fewer is better*: the stable-fingerprint dedup collapsed the ~55 repeats, so
  re-running gives you 67 distinct findings to reconcile, not a second wall of 122 to
  diff by hand. Both numbers count the **same population** - all stored findings,
  *including gate-rejected ones* - before vs. after dedup, so it is apples-to-apples.
  (Do not compare this 67 to the 32 in (a): (a) counts **surfaced** findings, (b)
  counts **all stored**. Different populations on purpose.)
- **The flywheel is live.** One run tuned a noisy rule down (CWE-209: 72 -> 6
  surfaced findings) and recorded 2 exploratory rule-gaps (both CWE-346) for a class
  no rule covered yet.

Both directions favor the harness even though one number goes up and the other
down: against the baseline Foundry covers **more** (32 > 15); against itself it
repeats **without multiplying** (67, not 122). Foundry's value is **not** being a
better bug-finder. It is a **governance and repeatability layer** over the same
model: an *enforced* confirmed-vs-needs-review tier, provenance per finding, a
declared bounded stop, stable identity across re-runs, and a corpus that sharpens
itself. One unbounded agent turn cannot give those, however well it behaves.

## Parameters of the run

| Field | Value |
|---|---|
| Target | langflow 1.7.3 (fixed, downloaded not copied) |
| Model (both arms) | claude-sonnet-4-6 (through the Cursor SDK) |
| Scope | **289** function-level units across **25** v1 modules + `helpers/flow.py` |
| Foundry LLM calls | **16** (12 batched Detector + 4 batched Triage) |
| Foundry tokens | **2,053,308** (cap 6,000,000, not exhausted) |
| Foundry stop | coverage-complete (all 289 units) |
| Baseline tokens | **213,121** in one single unbounded agent turn |

## Foundry findings 

58 findings from 61 candidates, decided by the Triager + evidence gate:

| Veredict | Count |
|---|---|
| **true-positive** (confirmed) | 28 |
| **needs-review** | 4 |
| **false-positive** (rejected) | 26 |

The **32 surfaced** findings (true-positive + needs-review) by severity:
**3 critical, 11 high, 18 medium**. By weakness class:

| Class | Surfaced | |
|---|---|---|
| CWE-639 (IDOR / missing ownership) | 10 | |
| CWE-209 (error info leak) | 6 | *(was 72 before the rule was tuned - see the flywheel)* |
| CWE-22 (path traversal) | 4 | |
| CWE-862 (missing authz) | 4 | |
| CWE-113 (header injection) | 2 | |
| CWE-312 (sensitive-data exposure) | 2 | |
| CWE-346 (origin validation) | 2 | |
| CWE-89 (SQL injection) | 1 | |
| CWE-94 (code injection) | 1 | |

The 26 rejected candidates never reach a reader: the harness surfaces only what
survives the gate (Constitution II). A plain agent has no such internal tier - what
it prints is what you get.

## Headline comparison (`out/comparison.md`)

| Metric | Foundry | Baseline | Better when |
|---|---|---|---|
| Findings surfaced (confirmed + needs-review) | 32 | 15 | - |
| Confirmed / needs-review | **28 / 4** (gate-enforced) | 14 / 1 (self-declared) | see note |
| Confirmed citation resolution (survives the gate) | 100% | 100% | higher |
| Hallucinated citations (confirmed set) | 0 | 0 | lower |
| Hallucinated citations (all) | 0 | 0 | lower |
| Structural completeness | 100% | 100% | higher |
| Duplicate rate (within one run) | 2% | 0% | lower |
| **Provenance reconstructable** | **yes** | **no** | yes |
| **Bounded stop** | **declared** (289 units) | **none** | declared |
| Tokens spent | 2,053,308 (~10x) | 213,121 | see note |

### Key findings

- **The citation quality tied (100% / 0 / 0).** A capable model, asked in good
  faith for rigor, largely delivered it. We did not make the baseline weak to
  manufacture a gap, so we report the tie plainly.
- **The confidence tier is the real difference.** The baseline labeled **14 of its
  15** findings "true-positive". That tier is only a hope that the model declares
  its own doubt: nothing enforces it. Foundry confirmed **28** and held **4** as
  "needs-review", and a finding reaches confirmed *only if its citations resolve
  against the real source*. A reviewer consuming the baseline cannot know which
  claims were checked; a reviewer consuming Foundry can, because the gate forces the
  separation instead of trusting the model to self-declare it.
- **More findings is completeness, not cleverness.** Foundry's 32 vs the baseline's
  15 is the difference between an exhaustive per-unit sweep and a single turn that
  curates a short list and drops the long tail. Same model; different discipline.
- **More tokens.** Foundry is not cheaper here - it spends ~10x to cover
  all 289 units under a *declared cap*, versus one unbounded turn. The spend buys
  coverage + gate + dedup, not a smarter model.
- **Where the tie is fragile vs where Foundry is guaranteed.** The baseline's clean
  citations are a *hope* that holds for this model, this scope, this prompt. A
  weaker model, a bigger scope, or a sloppier prompt breaks it. Foundry's 100% is a
  *guarantee by construction*: the same automatic gate always runs and demotes
  anything it cannot verify.

## An auditable true positive

One finding from the Langflow run, shown end to end, so you can see what
"auditable" means in practice.

**The bug.** In `src/backend/base/langflow/helpers/flow.py`, Langflow builds a
Python function as a text string, using a name the user controls (an input's
`display_name`), and then runs that string with `exec()`. The name is only
lowercased and has spaces swapped for underscores, so a crafted name can inject
its own code. Foundry rated it **true-positive, critical, CWE-94 (code injection)**.

**The proof is three lines of real code**, each cited by the model and checked
automatically by Foundry against the actual file:

| Line | What it shows |
|---|---|
| `flow.py:280` | The user-controlled name is pasted into generated source code |
| `flow.py:300` | That generated code becomes a function definition |
| `flow.py:327` | The function is executed with `exec()` |

If any of those line references had been wrong, the evidence gate would have
downgraded the finding to `needs-review` instead of `true-positive`.

**How to check it yourself:**

1. Open `out/findings/run_7b35d578cfd2.md` and search for `fp_fbde3053ed1387d0`
   (the finding's permanent ID).
2. Open `flow.py` at lines 280, 300 and 327 and confirm the chain.
3. Optionally, search `out/provenance.jsonl` for `ev_bfa11e88b7bc` (detection) and
   `ev_646b334987b0` (triage) to see the exact model calls and token usage behind
   the verdict.

The finding was first found in an earlier run and recognized as the same issue in
this one, so its ID and evidence trail stayed the same. That's what lets a
reviewer triage it once rather than every run.

**Why it matters:** the baseline (a single agent prompt) gives you one long
transcript. Foundry gives you, for each finding, the lines that prove it, a check
that those lines are real, and a record of how the verdict was reached.

The same run found two more critical issues: path traversal leading to arbitrary
directory deletion in `knowledge_bases.py` (`delete_knowledge_base` and
`delete_knowledge_bases_bulk`), where user input reaches
`shutil.rmtree(kb_root / user_input)`.

## The evidence gate in this run

Every confirmed finding's citations resolved, so the gate demoted none this run.
That is the strong model again - and it is exactly why the gate matters as a
*guarantee*, not a filter that only fires sometimes: regardless of whether a given
model hallucinates, the gate makes sure nothing reaches `true-positive` without
machine-checked evidence. (`FOUNDRY_LLM=mock` emits bad citations on purpose so you
can watch the gate demote them.)

## Dedup and stability across runs

The Foundry pipeline was run **twice** (independent LLM calls). These counts are the
**stored** row of the funnel (surfaced + rejected, since dedup tracks the whole
store): the representative run above stored **58**, the other run stored **64** - not
to be confused with the **32** *surfaced* from the representative run. The second run
is here **only to exhibit this property** - on unchanged code it learns nothing new;
it stands in for the next time you run the pipeline (e.g. a later commit), where the
dedup below is what lets you triage only the delta:

- The store holds **67 distinct fingerprints across the two runs, not 122** (the
  naive sum). Re-running did **not** produce a second wall of findings.
- **56 fingerprints recurred** in both runs and collapsed onto their existing
  identity (`seen_count > 1`) instead of duplicating - a ~90% overlap despite model
  non-determinism.
- The identity is `(file, weakness_class, symbol)`, deliberately without a line
  number, so it survives code edits and model jitter. Example: the `flow.py` exec
  finding above carries the same fingerprint `fp_fbde3053ed1387d0` in both runs (and
  in the narrow run too).

One agent turn has no identity between runs: run it twice and you get two unrelated
blobs to diff by hand.

## Rule gaps and the flywheel (detection -> prevention)

The flywheel showed up in **three** concrete ways in this run.

**(a) Sharpening a noisy rule (the "tune the rule" step).** The first wide run fired
the `CWE-209` error-info-leak rule on the pervasive `HTTPException(detail=str(e))`
idiom - **72** near-identical findings, technically valid but low-signal noise, not
72 distinct bugs. That is itself a flywheel signal: a noisy rule is something to
sharpen, not a pile to argue with. We tightened
`rules/py-error-info-leak.yaml` to confirm only genuinely sensitive leaks
(tracebacks, `repr(exc)`, DB/filesystem/subprocess errors, paths/queries) and to
treat the generic idiom as a single systemic note. Result on re-run: **CWE-209 went
from 72 to 6**, and the surfaced set became signal-dense (led by IDOR and path
traversal). Doing this required a real harness fix too - the rule's exclusion
criteria now flow into both the Detector digest and the Triager gate.

**(b) Foundry's own exploratory pass.** The Detector flagged a pattern **no rule
covered** and the Triager judged it worth review, logged in `out/rule-gaps.jsonl`:
**2 rule-gaps** in the representative run, both `CWE-346` (`Origin`/`X-Forwarded-For`
trust in `get_client_ip` and `install_mcp_config`). They recur in both runs, so the
log holds 4 records total (2 x 2) - the count the scorer reports. This is the spec's
FR-040/FR-042 loop running with no second tool.

**(c) The baseline as an illustrative gap source.** Ranging freely, the plain agent
surfaced `CWE-348` (use of less-trusted source) - a class outside the current
13-rule corpus. The scorer computes this gap deterministically (section 3 of
`out/comparison.md`); it becomes the next new rule.

Each new rule carries a `Provenance:` note. The four rules added earlier in the
flywheel (IDOR, header-injection, error-leak, sensitive-data) are already **live in
this run's 13-rule corpus** - the loop's first turn has already paid off.

**The second half - prevention everywhere (US-14 / FR-041).** CodeGuard rules are
*portable*: the same corpus this evaluation grows loads unchanged into an LLM coding
assistant as secure-coding guardrails. A class you teach Foundry to *detect* in
finished code becomes a class the assistant *prevents* at the keystroke, in every
editor, before the next evaluation runs. (The `codeguard-*` rules governing this very
workspace are that same format, already deployed that way.)

## The scale contrast (narrow run, `out-narrow/`)

Run over just 12 curated modules (107 units), the story is different - and that
difference is the point:

- At small scope the single-shot baseline **keeps up on breadth**; it even ranged
  wider than the starting corpus. The governance wins (gate, provenance, bounded
  stop, dedup) are present but the raw counts look like a tie.
- At full v1 scope the baseline **cannot** hold 25 modules in one turn - it curates
  ~15 headline items, while Foundry's per-unit sweep surfaces 32 gated, deduped,
  provenanced findings. The harness's value grows with scope.

This is why "widen the scope" is the honest stress test, and why the wide run is the
canonical one.

## Second target: MLflow

To validate that Foundry's governance properties hold beyond a single target, a
full-scope sweep was run against [MLflow](https://github.com/mlflow/mlflow) v2.9.0:
a significantly larger codebase than Langflow.

| Field | Value |
|---|---|
| Target | mlflow 2.9.0 |
| Model | claude-sonnet-4-6 (Cursor SDK) |
| Scope | **830** function-level units across server handlers, artifact storage, tracking store, auth, and file/URI utilities |
| LLM calls | **41** (34 batched Detector + 7 batched Triage) |
| Tokens | **4,816,743** (cap 6,000,000, not exhausted) |
| Stop | coverage-complete (all 830 units); trailing TP yield 0.17 |

**Findings: 136 total** —> 13 true-positive, 110 needs-review, 13 false-positive.
**123 surfaced** (true-positive + needs-review) by weakness class:

| Class | Surfaced |
|---|---|
| CWE-862 (missing authz) | 54 |
| CWE-22 (path traversal) | 34 |
| CWE-639 (IDOR / missing ownership) | 12 |
| CWE-209 (error info leak) | 8 |
| CWE-918 (SSRF) | 5 |
| CWE-312 (sensitive-data exposure) | 4 |
| CWE-113 (header injection) | 3 |
| CWE-94 (code injection) | 1 |
| CWE-129 (improper validation of array index) | 1 |
| CWE-89 (SQL injection) | 1 |

The CWE-22 findings concentrate in MLflow's artifact storage layer
(`local_artifact_repo.py`, `ftp_artifact_repo.py`, `sftp_artifact_repo.py`,
`hdfs_artifact_repo.py`, `databricks_artifact_repo.py`) and the file-handling
utilities (`file_utils.py`, `uri.py`). This matches MLflow's known CVE history
for path traversal (CVE-2023-6909, CVE-2023-6977).

**What this confirms at larger scale:**

- The evidence gate, provenance trail, and bounded stop hold at ~3x the unit
  count of Langflow with no configuration changes beyond the scope globs and
  output directory. Cross-run dedup was not re-tested here (one full run only);
  it is demonstrated on Langflow above.
- Foundry's per-unit enumeration surfaces a proportionally larger finding set as
  scope grows — 123 surfaced at 830 units vs 32 at 289, roughly linear. A single
  agent turn cannot hold 830 units in one context window.
- The 13-rule corpus transfers directly to a different codebase without
  modification. The same rules that found path traversal in Langflow's
  `knowledge_bases.py` found it in MLflow's artifact repos.

### Reproduce

```bash
# fetch target
bash scripts/fetch_target.sh mlflow

# run
python -m foundry_poc.cli --config config-mlflow.yaml run
```

## Antares localization: repo-size constraint and honest assessment

The `localize` command (Antares + Foundry) was evaluated on both Langflow and
MLflow. The results were clear: **Antares did not localize vulnerable files on
either target.** Understanding why, and what it means, is important context for
the overall system.

### Localized runs on large repos (like Langflow or MLflow)

| Run | Target | Repo size | Units analyzed | Candidates | True-positives |
|---|---|---|---|---|---|
| run_95a5816f18ab | Langflow v1.7.3 | **~175 MB** | 53 | 3 | **0** |
| run_9d4f741a4b29 | MLflow v2.9.0 | **~112 MB** | 70 | 2 | **0** |

Antares pointed the pipeline at entirely wrong areas:
- On **MLflow**, it directed Foundry to `_promptlab.py` and `experiments.py`
  instead of the artifact storage layer (`local_artifact_repo.py`,
  `sftp_artifact_repo.py`, etc.) where the known CVEs (CVE-2023-6909,
  CVE-2023-6977) actually live.
- On **Langflow**, it pointed to `settings/base.py` instead of `flow.py`
  (critical exec vulnerability) or the v1 API handlers where the full-scope
  run found 28 true-positives.

Compare this to the full-scope `run` results on the same repos: **28
true-positives on Langflow, 13 on MLflow**. Foundry's governed pipeline works
fine at any scale: the localizer (Antares) was the bottleneck.

### Why: the Antares paper explains this

The [Antares paper](https://arxiv.org/pdf/2608.02407) (Section 8.3, Figure 6)
shows that localization accuracy falls sharply with repository size, reaching
near-floor accuracy above 10 MB (the tier table is in
[LOCALIZER.md](LOCALIZER.md#repository-size-constraint)). Langflow at ~175 MB
and MLflow at ~112 MB are **10–17× beyond** the start of that worst tier. The
15-command interaction budget cannot cover enough of a 100+ MB codebase for the
search-verify-refine strategy to work. This is the documented behavior of the
model, not a bug.

### Small repos: Antares localization results

To show that Antares localization works when the repo fits within the model's
effective range, three smaller targets were selected and evaluated:

| Target | Version | Size (total) | Python src | Known CVE | CWE |
|---|---|---|---|---|---|
| **bottle** | 0.12.19 | ~862 KB | ~158 KB | CVE-2020-28473 | CWE-113 |
| **PyYAML** | 5.3.1 | ~848 KB | ~442 KB | CVE-2020-14343 | CWE-502 |
| **Werkzeug** | 2.3.7 | ~1.9 MB | ~698 KB | CVE-2024-34069 | CWE-94 |

**Antares localization results (standalone `antares query`):**

| Target | CWE | Files Antares returned | Correct? | Time |
|---|---|---|---|---|
| **PyYAML** | CWE-502 | `lib/yaml/constructor.py`, `lib/yaml/loader.py` | **Yes** — constructor.py is where unsafe object instantiation lives | 44–57s |
| **Werkzeug** | CWE-94 | `src/werkzeug/debug/console.py`, `debug/__init__.py`, `debug/tbtools.py` | **Yes** — the debug module is where the eval/exec code injection surface lives | 30–55s |
| **bottle** | CWE-113 | `bottle.py` (1st run), `plugins/sqlite/bottle_sqlite.py` (2nd run) | **Mixed** — 1st run correct, 2nd run pointed to a plugin instead of the main file | 30–39s |

By contrast, the same standalone `antares query` on Langflow ran for over 2.5
minutes and then failed to produce valid output, and on MLflow it was still
running after 10 minutes and had to be killed. On repos under 2 MB, Antares
completes in under a minute and returns the right files; on repos over 100 MB,
it hangs, fails, or (as in the localized runs above) points to the wrong areas.

**Foundry localized pipeline results (`localize --cwe`):**

| Target | CWE | Antares scope | Units analyzed (vs full) | Foundry findings |
|---|---|---|---|---|
| **Werkzeug** | CWE-94 | `src/werkzeug/debug/*.py` | 82 / 702 (88% reduction) | 0 candidates |
| **PyYAML** | CWE-502 | `lib/yaml/*.py` | 295 / 295 (flat package, no reduction) | 0 candidates |
| **bottle** | CWE-113 | `plugins/sqlite/*.py` | 10 / 327 (97% reduction) | 0 candidates |

Full-scope `run` on the same repos also produced 0 candidates. These repos are
**the libraries themselves**: Foundry's rules flag unsafe *use* of an API in
application code, not a library's own implementation of it (see
[LOCALIZER.md](LOCALIZER.md#key-insight-application-code-not-libraries)).

This does not diminish the Antares localization results: Antares correctly
identified the vulnerable modules in 2 out of 3 repos. For application-level
targets (like Langflow and MLflow), the full `run` command found real
vulnerabilities (28 TP on Langflow, 13 TP on MLflow). The localization step
and the detection step address different parts of the problem.

### How to reproduce

```bash
# fetch all targets (including the three small ones)
bash scripts/fetch_target.sh

# localized runs on small repos
python -m foundry_poc.cli --config config-bottle.yaml localize --cwe CWE-113
python -m foundry_poc.cli --config config-pyyaml.yaml localize --cwe CWE-502
python -m foundry_poc.cli --config config-werkzeug.yaml localize --cwe CWE-94
```

### Honest framing

Antares is a 1B-parameter model that runs locally in under a minute. It was
designed and benchmarked on repositories in the sub-megabyte to low-megabyte
range, where its search-verify-refine strategy is effective. Expecting it to
localize vulnerabilities in a 100+ MB codebase is like expecting _grep_ to
replace a full static analyzer: it is the wrong tool for that job.

Which mode to use at each repo size is covered in
[LOCALIZER.md](LOCALIZER.md#when-to-use-each-mode). In short: `localize` on small
repos, `run` on large ones. Repo size only limits Antares's localization step;
Foundry's detection, triage and governance properties work the same at any size.

This is not a dismissal of Antares: it is a compact, local, fast tool that
does what it was trained to do within its documented operating range. The
constraint is a property of the model architecture (1B parameters, 15-turn
budget), not a flaw, and it is documented transparently in the
[Antares paper](https://arxiv.org/pdf/2608.02407).

## PyGoat: Antares + Foundry integration demo (the proof)

The previous sections showed that Antares fails on large repos and that small
library repos localize correctly but yield no Foundry findings. This demo
answers the blocking question: **does Antares + Foundry `localize` deliver real
findings at lower cost than a full `run`?**

The target is [PyGoat](https://github.com/adeyosemanputra/pygoat), OWASP's
intentionally vulnerable Django application. At **1.1 MB** (70+ Python files
across multiple Django apps), it sits squarely in Antares's effective range.
Crucially, it is **application code** — it calls `pickle.loads()`, `eval()`,
`subprocess.Popen(shell=True)`, `.objects.raw()`, and `requests.get()` on
user input, which are exactly the patterns Foundry's 13-rule corpus detects.

### Step 1: Antares localization (standalone)

| CWE | Antares file(s) | Correct? | Time |
|---|---|---|---|
| CWE-78 (shell injection) | `introduction/mitre.py` | **Yes** — `subprocess.Popen(command, shell=True)` at line 233 | 22s |
| CWE-94 (code injection) | `introduction/mitre.py` | **Yes** — `eval(expression)` at line 218 | 28s |
| CWE-89 (SQL injection) | `PyGoatBot.py` | **Partial** — SQL-related file, but main `.objects.raw()` is in `introduction/views.py` | 43s |
| CWE-502 (deserialization) | *(none)* | **Miss** — model exhausted budget without submission | 56s |

**2 out of 4 CWEs correctly localized, 1 partial, 1 miss.** This is consistent
with the paper's ~33% hit@any benchmark average (macro across all sizes), and
substantially better than the 0/2 on Langflow and MLflow.

### Step 2: Localized run (_localize --cwe CWE-78_)

Antares narrowed scope from **180 units** (24 files, full app) to **128 units**
(8 files in "introduction"). Foundry ran on the narrowed scope.

| Field | Value |
|---|---|
| Run | run_2dc0ca037d05 |
| Antares time | 22.2s |
| Antares file | introduction/mitre.py |
| Expansion | directory -> introduction/*.py |
| Units analyzed | **128** (vs 180 full scope, **29% reduction**) |
| Candidates | 28 |
| Surfaced (TP + needs-review) | **25** (23 true-positive, 2 needs-review) |
| False-positive | 3 |
| Tokens | **295,189** |

**Surfaced findings by CWE (25 total):**

| Class | Count | Example |
|---|---|---|
| CWE-798 (hardcoded secret) | 7 | JWT signed with literal `'csrf_vulneribility'`; plaintext `jack`/`jacktheripper` creds |
| CWE-862 (missing authz) | 3 | Unauthenticated write to server-side Python source files |
| CWE-78 (shell injection) | 3 | `subprocess.Popen(command, shell=True)` on user-controlled `ip` field |
| CWE-94 (code injection) | 3 | `eval(val)` on POST input; `ImageMath.eval()` on user string |
| CWE-327 (weak crypto) | 2 | MD5 used for password hashing |
| CWE-89 (SQL injection) | 2 | `.objects.raw()` with string-concatenated user input |
| CWE-22 (path traversal) | 2 | `open(os.path.join(dirname, user_input))` without containment check |
| CWE-502 (unsafe deser.) | 2 | `pickle.loads(cookie)` and `yaml.load(file, yaml.Loader)` |
| CWE-918 (SSRF) | 1 | `requests.get(url)` on unvalidated POST field |

All 23 true-positives passed the evidence gate with every citation resolved.

### Step 3: Full-scope run (cost baseline)

| Field | Value |
|---|---|
| Run | run_669a3689d714 |
| Units analyzed | **180** (all 24 files) |
| Candidates | 47 |
| Surfaced (TP + needs-review) | **45** (42 true-positive, 3 needs-review) |
| False-positive | 2 |
| Tokens | **420,358** |

**Surfaced findings by CWE (45 total):**

| Class | Count |
|---|---|
| CWE-798 (hardcoded secret) | 9 |
| CWE-862 (missing authz) | 8 |
| CWE-78 (shell injection) | 5 |
| CWE-22 (path traversal) | 4 |
| CWE-94 (code injection) | 4 |
| CWE-312 (sensitive-data) | 4 |
| CWE-327 (weak crypto) | 3 |
| CWE-502 (unsafe deser.) | 3 |
| CWE-209 (error info leak) | 2 |
| CWE-89 (SQL injection) | 2 |
| CWE-918 (SSRF) | 1 |

### Cost comparison: localize vs. full run

| Metric | `localize --cwe CWE-78` | Full `run` | Savings |
|---|---|---|---|
| Antares localization | 22s (local, free) | n/a | **Zero-cost** scope narrowing |
| Units analyzed | 128 | 180 | 29% fewer units |
| Foundry tokens | 295,189 | 420,358 | **125K tokens saved (30%)** |
| Wall-clock time | ~4.2 min (+ 22s Antares) | ~6 min | ~2 min faster |
| Surfaced findings | 25 | 45 | Coverage trade-off (by design) |
| Critical findings | 8 | 14 | Coverage trade-off (by design) |
| CWE classes covered | 9 | 11 | 82% of classes |

**The localized run saves 30% of Foundry's LLM tokens** (125K fewer tokens
billed through the Cursor SDK). Antares itself runs locally on Apple Silicon
at zero cost: no API calls, no token billing. The trade-off is coverage:
the localized run scans only the area Antares identified, so findings in other
parts of the codebase (e.g. "dockerized_labs") are not surfaced. This is the
intended design: _localize_ answers "is this CWE in my code and where?" at
lower cost, while _run_ provides the full posture.

Antares was asked about **CWE-78** (shell injection) and correctly pointed to
"introduction/mitre.py". Once the localizer expanded to "introduction/*.py",
Foundry ran **all 13 rules** on those files (not just CWE-78). This is by
design: the advisory narrows WHERE to look; Foundry checks for EVERYTHING in
that area. The result: the targeted CWE-78 findings plus 8 additional CWE
classes discovered as a bonus of comprehensive scanning on the narrowed scope.

Of the full run's **14 critical** findings,
the localized run captured **8** (57%):

- **3 missed — outside scope.** These live in "dockerized_labs" (pickle
  deserialization, missing authz, sensitive data exposure), which Antares did not
  include. This is an expected trade-off: a narrowed scope excludes areas.
- **3 missed, in scope but not flagged.** "introduction/apis.py:130" (CWE-94,
  file-write code injection) and "introduction/mitre.py:215,238" (CWE-862,
  missing auth on the eval and nmap endpoints) were in files the localized run
  analyzed, but the model classified these units differently across the two runs.
  This is LLM non-determinism: the same file seen under a different scope and
  batch context can produce different findings.

This is the expected trade-off of scope narrowing: the localized run delivered
25 surfaced findings (23 TP), covering the targeted weakness (CWE-78 shell
injection) plus adjacent patterns discovered by running all 13 rules on the
narrowed area, in 4 minutes at 295K tokens. The full run found more (45 surfaced, 14
critical) in 6 minutes at 420K tokens, because it analyzed the entire
codebase. The localized run is both faster and cheaper; the full run is more
comprehensive.

### What "critical" means here

Severity is assigned by Foundry's Triager based on the "severity.scheme:
low_medium_high_critical" policy in the config file. The Triager assesses each
finding's exploitability (is user input directly reachable? is there a
sanitization bypass?) and impact (RCE, data loss, auth bypass) to assign a
severity tier. This is the model's judgment under the configured policy, not a
fixed label from a CVE database. Because it is model-assigned, the same
pattern can receive different severity labels across runs.

The evidence gate (citation resolution) is deterministic — a finding either
resolves or it does not. But severity assignment and which patterns the model
flags are inherently non-deterministic across runs. This is why the full _run_
remains the authoritative mode for comprehensive posture: it analyzes every
unit, giving the model the broadest context to surface and classify findings.

### What this proves

1. **Antares correctly localizes at zero cost.** It found "introduction/mitre.py"
   for CWE-78 in 22 seconds using a local 1B model on Apple Silicon. No API
   calls, no tokens billed.
2. **Foundry finds real vulnerabilities** in the narrowed scope. 23 true-positives,
   all with resolved evidence citations: the targeted CWE-78 plus 8 additional
   CWE classes found by running all 13 rules on the narrowed area.
3. **The integration saves tokens.** The localized run used 295K Foundry tokens
   vs. 420K for the full run, a 30% reduction (125K tokens saved). Antares's
   scope narrowing is what makes this possible: fewer units to analyze means
   fewer LLM calls.
4. **The trade-off is coverage, by design.** The localized run found 25 findings
   in the area Antares identified; the full run found 45 across the entire
   codebase. This is not a flaw, it is the intended model: _localize_ for fast,
   cheaper advisory response; _run_ for comprehensive posture.
5. **The modes are complementary.** _localize_ provides **speed** (22s to narrow
   + 4 min to analyze) and **lower cost** (30% fewer Foundry tokens). _run_
   provides **completeness** (all 45 findings, all 14 criticals, all 11 CWE
   classes). Use _localize_ when an advisory drops; use _run_ when you need the
   full picture.

### Reproduce

```bash
# fetch
bash scripts/fetch_target.sh pygoat

# localized run (Antares + Foundry)
python -m foundry_poc.cli --config config-pygoat.yaml localize --cwe CWE-78 \
  --endpoint http://127.0.0.1:8080/v1/completions

# full-scope baseline
python -m foundry_poc.cli --config config-pygoat.yaml run
```

## Honest interpretation

- **Foundry is the same model; it is not a smarter bug-finder.** On shared classes
  the arms agree, and citation quality ties.
- **At scale Foundry surfaces more only because it enumerates exhaustively.** That
  is a harness property (completeness under a bounded budget), and it includes a
  long tail a curated pass omits, which is exactly why rule tuning (the flywheel)
  matters.
- **Foundry is not cheaper** (~10x the tokens) but the spend is bounded by a
  declared cap and buys coverage + gate + dedup.
- **The provable value is governance and repeatability:** enforced
  confirmed/needs-review, provenance per finding, a declared bounded stop, stable
  identity across runs, and a corpus that both grows (rule-gaps) and sharpens (rule
  tuning). One agent turn cannot guarantee these, however well it behaves.

### Reproduce it

```bash
export CURSOR_API_KEY=...
python -m foundry_poc.cli run                 # canonical wide run -> out/
python -m foundry_poc.cli baseline
python -m foundry_poc.cli score --foundry out/foundry-<run>.json \
                                --baseline out/baseline-<run>.json
python -m foundry_poc.cli run                 # again, to see cross-run dedup
python -m foundry_poc.cli status

# the narrow scale-contrast:
python -m foundry_poc.cli --config config-narrow.yaml run
```
