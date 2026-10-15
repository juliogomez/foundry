# CodeGuard integration: from detection to prevention

## What is Project CodeGuard

[Project CodeGuard](https://project-codeguard.org/) is an open-source, model-agnostic
security framework that embeds secure-by-default rules into AI coding agent workflows.
Originally developed by Cisco and now donated to the
[Coalition for Secure AI (CoSAI)](https://www.coalitionforsecureai.org/), it provides
security rules that guide AI assistants (Cursor, GitHub Copilot, Claude Code, Codex,
Windsurf, and others) to generate secure code automatically.

CodeGuard rules operate *before, during, and after* code generation. They steer
agents toward secure patterns during planning, prevent vulnerabilities from being
introduced during generation, and validate correct usage during automated code review.
They are the **prevention** layer: the point in the loop where a known weakness
class stops being something you *find* and becomes something you *prevent*.

## The closed loop: detection investment compounds into prevention

The Foundry spec describes a **detection→prevention flywheel** (US-14): what
the evaluation finds today should feed back into rules that prevent it tomorrow.
But the spec deliberately leaves the mechanism unspecified. This PoC closes it
concretely: the `synthesize` command bridges Foundry's rule-gap log directly into
production-ready CodeGuard rules.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   THE DETECTION→PREVENTION FLYWHEEL                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────┐       ┌───────────┐       ┌─────────────┐              │
│   │  Antares │──────▶│  Foundry  │──────▶│ Synthesizer │              │
│   │ Advisory │ CWE + │  Detect + │ gaps  │  Gap→Rule   │              │
│   │ → Scope  │ files │  Triage   │       │             │              │
│   └──────────┘       └───────────┘       └──────┬──────┘              │
│                                                  │                      │
│                    ┌─────────────────────────────┐│                      │
│                    │                             ││                      │
│                    ▼                             ▼│                      │
│   ┌────────────────────┐         ┌──────────────────────────┐          │
│   │ Foundry rules/     │         │ CodeGuard .cursor/rules/ │          │
│   │ (detection YAML)   │         │ (prevention markdown)    │          │
│   │                    │         │                          │          │
│   │ Future runs catch  │         │ AI assistants prevent    │          │
│   │ existing instances │         │ new instances at the     │          │
│   └────────────────────┘         │ keystroke, org-wide      │          │
│                                  └──────────────────────────┘          │
│                                           │                             │
│                                           │ fewer vulns                 │
│                                           ▼ next evaluation             │
│                                  ┌──────────────────┐                   │
│                                  │  Shrinking       │                   │
│                                  │  attack surface  │                   │
│                                  └──────────────────┘                   │
└─────────────────────────────────────────────────────────────────────────┘
```

The key insight: **each detection dollar spent once compounds into prevention
everywhere, forever**. A one-time Foundry observation becomes a permanent CodeGuard
rule that loads into every developer's editor across the organization. The population
of vulnerabilities that the next evaluation has to find *shrinks*.

## How it works in this PoC

### Step 1: Foundry identifies a gap

During a governed evaluation, the Detector's exploratory pass flags patterns that
no existing rule covers. When the Triager confirms such a pattern as `true-positive`
or `needs-review`, the Orchestrator logs it:

```json
{
  "weakness_class": "CWE-346",
  "symbol": "get_client_ip",
  "unit": "src/backend/.../mcp_projects.py::get_client_ip",
  "verdict": "true-positive",
  "why": "The client IP is taken verbatim from the attacker-controlled X-Forwarded-For header..."
}
```

### Step 2: `foundry synthesize` generates prevention rules

```bash
python -m foundry_poc.cli synthesize
```

The synthesizer:
1. Reads `out/rule-gaps.jsonl` and deduplicates by CWE
2. For each unique gap, calls the LLM with the gap context and a structured prompt
3. Generates **two** outputs per gap:
   - A **CodeGuard prevention rule** (`.cursor/rules/codeguard-py-<slug>.mdc`), the
     IDE-level guardrail that prevents the weakness at authoring time
   - A **Foundry detection rule** (`rules/py-<slug>.yaml`), which ensures future runs
     catch existing instances of the same pattern

### Step 3: prevention deploys automatically

The generated CodeGuard markdown rule is placed in the target project's
`.cursor/rules/` directory. The next time any developer opens that project in their
AI-assisted IDE, the rule is active. No deployment, no pipeline, no manual
configuration. The prevention *is* the file.

The file has to be in the format the agent actually loads. Cursor reads project
rules only from `.mdc` files that start with a `---` frontmatter block. A `.md`
file with identical content in `.cursor/rules/` is silently ignored. Early versions of the
synthesizer wrote `.md` files, so those rules never reached the assistant. A canary
test in the [prevention experiment](PREVENTION.md#rule-delivery-what-we-learned)
caught it. The synthesizer now writes `.mdc` files with `alwaysApply: false` and a
`globs` scope. That means a rule attaches when the agent works on a matching file.
Cursor SDK agents also need `setting_sources=["project"]` to load project rules at all.

### Options

```
python -m foundry_poc.cli synthesize [--gaps-file PATH] [--output-dir PATH] [--cwe CWE-XXX]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `--gaps-file` | from config (`out/rule-gaps.jsonl`) | Override the rule-gaps source |
| `--output-dir` | `{target}/.cursor/rules/` | Override where CodeGuard rules land |
| `--cwe` | all gaps | Filter synthesis to one specific CWE |

## The self-referential proof

There is an intentional self-reference in this repository that proves the loop works:
the `codeguard-*` rules actively governing *this very workspace* right now are the
same format that `foundry synthesize` produces. The rules that prevent hardcoded
credentials, enforce input validation, and require safe cryptographic algorithms in
the code you write *while working on this PoC* are Project CodeGuard rules,
exactly the artifact the synthesizer generates.

This is not coincidence. It is the concrete manifestation of the thesis: what you
teach Foundry to *detect* in finished code becomes what CodeGuard *prevents* at the
keystroke, in every developer's editor, before the next evaluation ever runs.

## The full Cisco integration story

Three Cisco-originated projects form a single security loop:

| Project | Role | Input | Output |
|---------|------|-------|--------|
| **[Antares](https://huggingface.co/collections/fdtn-ai/antares)** | Scope reduction | Security advisory (CWE) | Ranked file list (likely-vulnerable locations) |
| **[Foundry](https://github.com/CiscoDevNet/foundry-security-spec)** | Governed detection + triage | Code scope + rules | Verified findings + rule-gaps |
| **[CodeGuard](https://project-codeguard.org/)** | IDE prevention | Rule-gaps | Always-on guardrails for AI coding agents |

The integration runs as:

1. **Antares** receives a CWE from a security advisory and identifies which files in
   the codebase are likely affected, reducing the search space from thousands of files
   to a targeted handful.

2. **Foundry** runs its governed pipeline over that narrowed scope: detection with
   evidence, triage with citations, deduplication with fingerprints, bounded by a
   token cap. Findings are verifiable. Gaps are logged.

3. **CodeGuard** (via the Synthesizer) converts confirmed gaps into prevention rules
   that deploy to every developer's IDE. The weakness class that was just detected
   becomes impossible to reintroduce.

4. The next Foundry evaluation finds **fewer vulnerabilities** because CodeGuard has
   been preventing them at authoring time. The attack surface contracts with each
   iteration of the loop.

This is not three products bolted together. It is one loop with three specializations:
**localize, evaluate, prevent**, where the output of each feeds the input of the next.

## Example: CWE-346 from gap to rule

The actual `rule-gaps.jsonl` in this PoC contains the following confirmed gap:

```json
{
  "weakness_class": "CWE-346",
  "symbol": "get_client_ip",
  "why": "The client IP is taken verbatim from the attacker-controlled
          X-Forwarded-For header without validating that the request
          actually arrived through a trusted proxy, allowing a remote
          attacker to spoof a loopback address and bypass the local-only
          check in install_mcp_config."
}
```

Running `python -m foundry_poc.cli synthesize --cwe CWE-346` produces:

**CodeGuard prevention rule** (`target/.cursor/rules/codeguard-py-cwe-346.mdc`):
A markdown rule that instructs AI coding assistants to never trust proxy headers
without validation, provides secure patterns for proxy trust configuration, and
includes an implementation checklist for developers.

**Foundry detection rule** (`rules/py-cwe-346.yaml`):
A YAML rule that catches existing instances of the same pattern in future Foundry
runs, ensuring the gap is no longer exploratory.

The CWE-346 gap that Foundry surfaced *once* is now:
- Caught automatically on every future evaluation (detection rule)
- Prevented from being introduced in new code (CodeGuard prevention rule)
- Active across every developer's IDE in the organization (portable markdown)

One observation, permanent protection. That is the flywheel.

## Real synthesis runs

The synthesizer was run against both confirmed gaps from the real evaluations:

```bash
python -m foundry_poc.cli synthesize --cwe CWE-346                            # Langflow gap
python -m foundry_poc.cli --config config-mlflow.yaml synthesize --cwe CWE-129  # MLflow gap
```

| Gap | Source | Tokens | Time | CodeGuard rule | Foundry rule |
|---|---|---|---|---|---|
| CWE-346 (proxy-header trust) | Langflow `get_client_ip` | ~28K | ~82s | [examples/synthesized/langflow-codeguard-py-cwe-346.mdc](../examples/synthesized/langflow-codeguard-py-cwe-346.mdc) | [rules/py-cwe-346.yaml](../rules/py-cwe-346.yaml) |
| CWE-129 (unchecked split index) | MLflow `_extract_run_id` | ~29K | ~93s | [examples/synthesized/mlflow-codeguard-py-cwe-129.mdc](../examples/synthesized/mlflow-codeguard-py-cwe-129.mdc) | [rules/py-cwe-129.yaml](../rules/py-cwe-129.yaml) |

Each synthesis costs roughly 1-2% of the evaluation that discovered the gap (the
Langflow sweep was ~2M tokens). The Foundry corpus grew from 13 to 15 rules; the
runs reported in [RESULTS.md](RESULTS.md) predate this and used the 13-rule corpus.

The CodeGuard rules land in the target's `.cursor/rules/` by default (not committed
here because `targets/` is fetched, not vendored), so copies live in
`examples/synthesized/`.

**Human review is required.** As generated, the CWE-346 rule cited two CVE IDs as
examples of the pattern; at least one (CVE-2023-45857, an axios token leak) does not
match it. The citation was replaced with the confirmed Langflow finding before
committing. Treat every synthesized rule as a pull request, not a deployment.
