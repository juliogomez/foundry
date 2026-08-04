"""Synthesizer: close the Foundry→CodeGuard flywheel by generating prevention rules.

Takes confirmed rule-gaps (EXPLORATORY findings that survived triage) and uses the
LLM to produce two artifacts per gap:

  1. A CodeGuard prevention rule (markdown, real format) for the target project's IDE.
     Prevents the weakness class at authoring time going forward.
  2. A Foundry detection rule (YAML sketch) for this repo's rules/ corpus. Catches
     existing instances on future runs.

This is the concrete mechanism that turns a one-time detection observation into
permanent, reusable prevention across every developer's editor.

See docs/CODEGUARD.md for the full integration story.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .budget import BudgetGovernor
from .config import Config
from .llm import LLMBackend, make_backend

CODEGUARD_RULE_TEMPLATE = """\
description: {description}
globs: {globs}
version: 1.0.0
---

rule_id: {rule_id}

{body}
"""

FOUNDRY_RULE_TEMPLATE = """\
id: {rule_id}
description: |
  {description}

  Provenance: auto-synthesized by `foundry synthesize` from rule-gap data.
  Source CWE: {cwe}. See out/rule-gaps.jsonl for original detection context.
languages: [{language}]
severity: {severity}
weakness_class: {cwe}
applies_to:
{applies_to}
trigger_when:
{trigger_when}
example_positive: |
  {example_positive}
example_negative: |
  {example_negative}
"""

SYNTHESIS_SYSTEM_PROMPT = """\
You are a security engineering expert who writes CodeGuard rules. CodeGuard is an \
open-source framework that embeds secure-by-default rules into AI coding agent \
workflows. Rules are loaded by AI coding assistants (Cursor, GitHub Copilot, Claude \
Code, etc.) and guide them to generate secure code automatically.

Your task: given a rule-gap (a weakness class that Foundry detected but had no \
prevention rule for), produce a production-ready CodeGuard rule.

Output ONLY a JSON object with these exact keys:
{
  "codeguard_description": "One-line summary for the rule frontmatter (max 100 chars)",
  "codeguard_globs": "Comma-separated glob patterns (e.g. **/*.py,**/*.pyi)",
  "codeguard_rule_id": "codeguard-N-slug format (e.g. codeguard-0-origin-validation)",
  "codeguard_body": "Full markdown body of the rule (## Title, guidance, examples, checklist)",
  "foundry_description": "2-3 sentence description for the Foundry detection YAML",
  "foundry_severity": "low | medium | high | critical",
  "foundry_applies_to": ["list of what code patterns this applies to"],
  "foundry_trigger_when": ["list of conditions that trigger the rule"],
  "foundry_example_positive": "One code snippet showing the vulnerability",
  "foundry_example_negative": "One code snippet showing the secure alternative"
}

Requirements for the CodeGuard body:
- Start with a ## heading naming the weakness class
- Include a concise explanation of the risk
- Provide concrete secure coding patterns with code examples
- Include a ### Implementation Checklist at the end
- Be actionable and specific to the language/framework
- Match the quality and depth of existing CodeGuard rules (200-500 lines typical)
"""


def load_gaps(gaps_file: Path) -> list[dict[str, Any]]:
    """Load and parse rule-gaps.jsonl, returning all gap entries."""
    if not gaps_file.exists():
        return []
    gaps = []
    for line in gaps_file.read_text().splitlines():
        line = line.strip()
        if line:
            gaps.append(json.loads(line))
    return gaps


def deduplicate_gaps(gaps: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Deduplicate gaps by CWE, keeping the richest entry per class."""
    by_cwe: dict[str, dict[str, Any]] = {}
    for gap in gaps:
        cwe = gap.get("weakness_class", "UNKNOWN")
        if cwe not in by_cwe:
            by_cwe[cwe] = gap
        else:
            existing = by_cwe[cwe]
            if len(gap.get("why", "")) > len(existing.get("why", "")):
                by_cwe[cwe] = gap
    return by_cwe


def _build_synthesis_prompt(gap: dict[str, Any]) -> str:
    """Build the user prompt for rule synthesis from a gap entry."""
    return (
        f"Generate a CodeGuard prevention rule for this rule-gap:\n\n"
        f"  Weakness class: {gap.get('weakness_class', 'UNKNOWN')}\n"
        f"  Affected symbol: {gap.get('symbol', 'unknown')}\n"
        f"  Source file/unit: {gap.get('unit', 'unknown')}\n"
        f"  Detection rationale: {gap.get('why', 'no rationale provided')}\n"
        f"  Verdict: {gap.get('verdict', 'true-positive')}\n\n"
        f"The rule must prevent this class of vulnerability from being introduced "
        f"in new code. Focus on the general pattern, not just this specific instance.\n\n"
        f"Language: Python (infer from the source context).\n"
    )


def _slug_from_cwe(cwe: str) -> str:
    """Convert a CWE like 'CWE-346' into a filename slug."""
    m = re.match(r"CWE-(\d+)", cwe)
    if m:
        return f"cwe-{m.group(1)}"
    return re.sub(r"[^a-z0-9]+", "-", cwe.lower()).strip("-")


def _parse_synthesis_response(text: str) -> dict[str, Any]:
    """Extract the JSON object from the LLM synthesis response."""
    from .llm import extract_json
    return extract_json(text)


def _mock_synthesis(gap: dict[str, Any]) -> dict[str, Any]:
    """Produce a deterministic mock response for offline testing."""
    cwe = gap.get("weakness_class", "CWE-000")
    symbol = gap.get("symbol", "unknown_func")
    why = gap.get("why", "vulnerability detected")

    return {
        "codeguard_description": f"Prevention rule for {cwe} ({symbol} pattern)",
        "codeguard_globs": "**/*.py,**/*.pyi",
        "codeguard_rule_id": f"codeguard-0-{_slug_from_cwe(cwe)}",
        "codeguard_body": (
            f"## {cwe} Prevention\n\n"
            f"Prevent {why.split(',')[0].lower()} in new code.\n\n"
            f"### Secure Pattern\n"
            f"- Validate all inputs from untrusted sources before use\n"
            f"- Use framework-provided security utilities\n"
            f"- Apply allowlist validation where applicable\n\n"
            f"### Implementation Checklist\n"
            f"- [ ] All untrusted inputs validated at trust boundary\n"
            f"- [ ] Framework security utilities used consistently\n"
            f"- [ ] Tests cover both positive and negative cases\n"
        ),
        "foundry_description": f"Detect {why.split(',')[0].lower()} (maps to {cwe}).",
        "foundry_severity": "high",
        "foundry_applies_to": [f"functions that handle {symbol}-like patterns"],
        "foundry_trigger_when": [why],
        "foundry_example_positive": f"  # Vulnerable: {symbol} uses untrusted input\n  value = request.headers.get('X-Forwarded-For')",
        "foundry_example_negative": f"  # Secure: validate before use\n  value = validate_trusted_proxy(request)",
    }


def synthesize_rule(
    gap: dict[str, Any],
    backend: LLMBackend,
    budget: BudgetGovernor,
) -> dict[str, Any]:
    """Synthesize a CodeGuard + Foundry rule pair from a single gap.

    Returns a dict with keys: codeguard_path_content, foundry_path_content, metadata.
    """
    import os

    cwe = gap.get("weakness_class", "UNKNOWN")
    slug = _slug_from_cwe(cwe)

    if os.environ.get("FOUNDRY_LLM", "cursor").lower() == "mock":
        parsed = _mock_synthesis(gap)
        usage = {"input_tokens": 100, "output_tokens": 200, "total_tokens": 300}
    else:
        budget.check()
        prompt = _build_synthesis_prompt(gap)
        text, usage = backend.complete(prompt, system=SYNTHESIS_SYSTEM_PROMPT)
        budget.record(usage["input_tokens"], usage["output_tokens"], usage["total_tokens"])
        parsed = _parse_synthesis_response(text)

    codeguard_content = CODEGUARD_RULE_TEMPLATE.format(
        description=parsed["codeguard_description"],
        globs=parsed["codeguard_globs"],
        rule_id=parsed["codeguard_rule_id"],
        body=parsed["codeguard_body"],
    )

    applies_to_yaml = "\n".join(f"  - {item}" for item in parsed.get("foundry_applies_to", []))
    trigger_when_yaml = "\n".join(f"  - {item}" for item in parsed.get("foundry_trigger_when", []))

    foundry_content = FOUNDRY_RULE_TEMPLATE.format(
        rule_id=f"codeguard-py-{slug}",
        description=parsed["foundry_description"],
        cwe=cwe,
        language="python",
        severity=parsed.get("foundry_severity", "high"),
        applies_to=applies_to_yaml,
        trigger_when=trigger_when_yaml,
        example_positive=parsed.get("foundry_example_positive", "# example"),
        example_negative=parsed.get("foundry_example_negative", "# secure example"),
    )

    return {
        "cwe": cwe,
        "slug": slug,
        "codeguard_content": codeguard_content,
        "codeguard_filename": f"codeguard-py-{slug}.md",
        "foundry_content": foundry_content,
        "foundry_filename": f"py-{slug}.yaml",
        "usage": usage,
        "parsed": parsed,
    }


def run_synthesis(
    cfg: Config,
    *,
    gaps_file: Path | None = None,
    output_dir: Path | None = None,
    cwe_filter: str | None = None,
) -> dict[str, Any]:
    """Full synthesis pipeline: load gaps, deduplicate, generate rules, write output.

    Returns a summary dict with paths and metadata.
    """
    gaps_path = gaps_file or cfg.rule_gaps_log
    if output_dir is None:
        output_dir = cfg.target_path / ".cursor" / "rules"

    output_dir.mkdir(parents=True, exist_ok=True)

    gaps = load_gaps(gaps_path)
    if not gaps:
        return {"status": "no-gaps", "message": f"No rule-gaps found in {gaps_path}"}

    unique_gaps = deduplicate_gaps(gaps)

    if cwe_filter:
        cwe_upper = cwe_filter.upper()
        unique_gaps = {k: v for k, v in unique_gaps.items() if k.upper() == cwe_upper}
        if not unique_gaps:
            return {
                "status": "no-match",
                "message": f"No gaps matching {cwe_filter} in {gaps_path}",
            }

    backend = make_backend(cfg.model, cfg.scratch_cwd)
    budget = BudgetGovernor(max_tokens=cfg.max_tokens)

    results = []
    for cwe, gap in unique_gaps.items():
        t0 = time.time()
        result = synthesize_rule(gap, backend, budget)
        result["duration_s"] = round(time.time() - t0, 1)

        codeguard_path = output_dir / result["codeguard_filename"]
        codeguard_path.write_text(result["codeguard_content"])
        result["codeguard_path"] = str(codeguard_path)

        foundry_path = cfg.rules_dir / result["foundry_filename"]
        foundry_path.write_text(result["foundry_content"])
        result["foundry_path"] = str(foundry_path)

        results.append(result)

    return {
        "status": "synthesized",
        "gaps_file": str(gaps_path),
        "output_dir": str(output_dir),
        "rules_generated": len(results),
        "budget": budget.summary(),
        "results": [
            {
                "cwe": r["cwe"],
                "codeguard_rule": r["codeguard_path"],
                "foundry_rule": r["foundry_path"],
                "duration_s": r["duration_s"],
            }
            for r in results
        ],
    }
