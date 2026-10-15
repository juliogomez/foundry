"""Foundry PoC command line.

  up          verify environment + scope, fetch target if needed
  models      list valid Cursor model slugs (requires CURSOR_API_KEY)
  run         run the Foundry pipeline over the in-scope target
  baseline    run the fair agentic baseline (single disciplined agent)
  score       compare Foundry vs baseline on pre-registered metrics
  localize    narrow scope with Antares, then run the Foundry pipeline
  synthesize  generate CodeGuard prevention rules from rule-gaps
  prevention  A/B test: do CodeGuard rules change what an AI agent writes?
  status      show the last run summary
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .config import load_config


def _cmd_up(args) -> int:
    cfg = load_config(args.config)
    print(f"system:        {cfg.system_name}")
    print(f"backend:       {cfg.backend}  (FOUNDRY_LLM={os.environ.get('FOUNDRY_LLM','cursor')})")
    print(f"model:         {cfg.model}")
    key = os.environ.get("CURSOR_API_KEY")
    print(f"CURSOR_API_KEY set: {'yes' if key else 'NO (set it before a real run, or use FOUNDRY_LLM=mock)'}")
    print(f"target:        {cfg.target_path}  @ {cfg.pinned_ref}")
    if not cfg.target_path.exists():
        print("  -> target not fetched. Run: bash scripts/fetch_target.sh")
    from .indexer import index_target
    from .rules import load_rules
    rules = load_rules(cfg.rules_dir)
    print(f"rules:         {len(rules)} loaded -> {[r.id for r in rules]}")
    if cfg.target_path.exists():
        units = index_target(cfg.target_path, cfg.include_globs, cfg.exclude_globs)
        print(f"units in scope: {len(units)} across {len({u.rel_file for u in units})} files")
    print(f"token cap:     {cfg.max_tokens}")
    return 0


def _cmd_models(args) -> int:
    from cursor_sdk import Cursor
    try:
        models = Cursor.models.list()
    except Exception as e:  # noqa: BLE001
        print(f"could not list models: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    for m in models:
        print(getattr(m, "id", getattr(m, "name", repr(m))))
    return 0


def _cmd_run(args) -> int:
    cfg = load_config(args.config)
    from .orchestrator import run_pipeline
    summary = run_pipeline(cfg, limit_units=args.limit)
    print(json.dumps(summary["meta"], indent=2))
    print(f"\nreport:          {summary['report_path']}")
    print(f"normalized json: {summary['normalized_path']}")
    print(f"raw candidates:  {summary['raw_candidates_path']}")
    print(f"tokens used:     {summary['budget']['total_tokens']} / {summary['budget']['max_tokens']}")
    return 0


def _cmd_baseline(args) -> int:
    cfg = load_config(args.config)
    from .baseline import run_baseline
    summary = run_baseline(cfg)
    print(json.dumps(summary["meta"], indent=2))
    print(f"\nbaseline raw:        {summary['raw_path']}")
    print(f"baseline normalized: {summary['normalized_path']}")
    return 0


def _cmd_score(args) -> int:
    cfg = load_config(args.config)
    from .scorer import score
    report = score(cfg, foundry_json=args.foundry, baseline_json=args.baseline)
    print(report["markdown"])
    print(f"\nwritten: {report['path']}")
    return 0


def _cmd_status(args) -> int:
    cfg = load_config(args.config)
    import sqlite3
    if not cfg.db_path.exists():
        print("no runs yet.")
        return 0
    conn = sqlite3.connect(str(cfg.db_path))
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM runs ORDER BY started_at DESC LIMIT 5").fetchall()
    for r in rows:
        budget = json.loads(r["budget_json"] or "{}")
        n = conn.execute(
            "SELECT COUNT(*) c FROM run_findings WHERE run_id=?", (r["run_id"],)
        ).fetchone()["c"]
        print(f"{r['run_id']}  status={r['status']}  findings={n}  "
              f"tokens={budget.get('total_tokens','?')}  stop={r['stop_reason']}")
    conn.close()
    return 0


def _cmd_synthesize(args) -> int:
    cfg = load_config(args.config)
    from .synthesizer import run_synthesis

    gaps_file = Path(args.gaps_file) if args.gaps_file else None
    output_dir = Path(args.output_dir) if args.output_dir else None

    result = run_synthesis(
        cfg,
        gaps_file=gaps_file,
        output_dir=output_dir,
        cwe_filter=args.cwe,
    )

    if result["status"] in ("no-gaps", "no-match"):
        print(result["message"])
        return 0

    print(f"\n{'='*60}")
    print("SYNTHESIZER: Foundry -> CodeGuard")
    print(f"{'='*60}")
    print(f"  gaps file:      {result['gaps_file']}")
    print(f"  output dir:     {result['output_dir']}")
    print(f"  rules generated: {result['rules_generated']}")
    print(f"  tokens used:    {result['budget']['total_tokens']}")
    for r in result["results"]:
        print(f"\n  [{r['cwe']}] ({r['duration_s']}s)")
        print(f"    CodeGuard rule: {r['codeguard_rule']}")
        print(f"    Foundry rule:   {r['foundry_rule']}")

    print(f"\n  The generated CodeGuard rules will be loaded by AI coding assistants")
    print(f"  in the target project to prevent this weakness class at authoring time.")
    return 0


def _cmd_localize(args) -> int:
    from .localizer import localize_and_run, DEFAULT_ENDPOINT
    endpoint = args.endpoint or DEFAULT_ENDPOINT
    antares_repo = Path(args.antares_repo).resolve() if args.antares_repo else None

    result = localize_and_run(
        cfg_path=Path(args.config),
        cwe=args.cwe,
        expand=args.expand,
        endpoint=endpoint,
        model=args.model,
        antares_repo=antares_repo,
        limit_units=args.limit,
    )

    loc = result["localizer"]
    pipeline = result["pipeline"]
    print(f"\n{'='*60}")
    print(f"LOCALIZER SUMMARY")
    print(f"{'='*60}")
    print(f"  antares files:   {loc['antares_files']}")
    print(f"  antares time:    {loc['antares_duration_s']}s")
    print(f"  expansion:       {loc['expansion_strategy']}")
    print(f"  scope globs:     {loc['scope_globs']}")
    print(f"  units analyzed:  {loc['units_narrowed']}")
    print(f"\n  foundry report:  {pipeline['report_path']}")
    print(f"  normalized json: {pipeline['normalized_path']}")
    print(f"  tokens used:     {pipeline['budget']['total_tokens']} / {pipeline['budget']['max_tokens']}")
    return 0


def _cmd_prevention(args) -> int:
    cfg = load_config(args.config)
    from . import prevention

    arms = args.arms.split(",") if args.arms else None
    tasks = args.tasks.split(",") if args.tasks else None
    if args.stage in ("generate", "all"):
        print("== generate ==")
        g = prevention.generate(cfg, reps=args.reps, workers=args.workers, arms=arms, task_ids=tasks)
        print(f"  scheduled={g['scheduled']} completed={g['completed']} "
              f"errors={g['errors']} already_done={g['already_done']}")
        if g["errors"]:
            print("  some trials failed; re-run the generate stage to retry them")
            return 1
    if args.stage in ("judge", "all"):
        print("== judge (Foundry, blind) ==")
        j = prevention.judge(cfg, max_tokens=args.judge_max_tokens)
        print(f"  run={j['run_id']} findings={len(j['reported'])} "
              f"tokens={j['budget']['total_tokens']}")
    if args.stage in ("report", "all"):
        r = prevention.report(cfg)
        print(r["markdown"])
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="foundry-poc", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default="config.yaml", help="path to config.yaml")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("up", help="verify env + scope").set_defaults(func=_cmd_up)
    sub.add_parser("models", help="list Cursor model slugs").set_defaults(func=_cmd_models)

    rp = sub.add_parser("run", help="run the Foundry pipeline")
    rp.add_argument("--limit", type=int, default=None, help="cap number of units (smoke test)")
    rp.set_defaults(func=_cmd_run)

    sub.add_parser("baseline", help="run the fair agentic baseline").set_defaults(func=_cmd_baseline)

    sp = sub.add_parser("score", help="compare foundry vs baseline")
    sp.add_argument("--foundry", required=True, help="path to foundry-<run>.json")
    sp.add_argument("--baseline", required=True, help="path to baseline-<run>.json")
    sp.set_defaults(func=_cmd_score)

    sub.add_parser("status", help="show recent runs").set_defaults(func=_cmd_status)

    synp = sub.add_parser("synthesize", help="generate CodeGuard prevention rules from rule-gaps")
    synp.add_argument("--gaps-file", default=None,
                      help="path to rule-gaps.jsonl (default: from config store)")
    synp.add_argument("--output-dir", default=None,
                      help="output dir for CodeGuard rules (default: target/.cursor/rules/)")
    synp.add_argument("--cwe", default=None,
                      help="filter to a specific CWE (e.g. CWE-346)")
    synp.set_defaults(func=_cmd_synthesize)

    pp = sub.add_parser("prevention", help="A/B test CodeGuard rules on an AI coding agent")
    pp.add_argument("--stage", default="all", choices=["generate", "judge", "report", "all"])
    pp.add_argument("--reps", type=int, default=2, help="repetitions per task and arm")
    pp.add_argument("--workers", type=int, default=6, help="concurrent agent sessions")
    pp.add_argument("--arms", default=None,
                    help="comma-separated subset of: none,codeguard,codeguard+foundry")
    pp.add_argument("--tasks", default=None, help="comma-separated task ids (default: all)")
    pp.add_argument("--judge-max-tokens", type=int, default=3_000_000)
    pp.set_defaults(func=_cmd_prevention)

    lp = sub.add_parser("localize", help="narrow scope with Antares, then run Foundry")
    lp.add_argument("--cwe", required=True, help="CWE ID (e.g. CWE-22) passed to Antares CLI")
    lp.add_argument("--expand", default="directory", choices=["exact", "directory", "parent", "full"],
                    help="scope expansion strategy (default: directory)")
    lp.add_argument("--endpoint", default=None,
                    help="mlx-lm endpoint (default: http://127.0.0.1:8080/v1/completions)")
    lp.add_argument("--model", default=None, help="Antares model path override")
    lp.add_argument("--antares-repo", default=None,
                    help="path to Antares repo (for auto-starting the server)")
    lp.add_argument("--limit", type=int, default=None, help="cap units (smoke test)")
    lp.set_defaults(func=_cmd_localize)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
