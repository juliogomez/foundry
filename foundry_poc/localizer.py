"""Localizer: Antares CLI as a scope-reduction step before Foundry analysis.

Calls `antares query` to get a ranked file shortlist for a given CWE, then
expands the scope to include neighboring files (configurable), and patches
the Foundry config to run the pipeline on that narrowed scope only.

Prerequisites:
  - `antares` on PATH (pip install -e ../antares/explore/antares-cli)
  - mlx-lm server running on the configured endpoint
  - Target repo fetched (scripts/fetch_target.sh)

See docs/LOCALIZER.md for setup and usage.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


DEFAULT_ENDPOINT = "http://127.0.0.1:8080/v1/completions"
DEFAULT_MODEL = "antares-1b-shim"
EXPANSION_STRATEGIES = ("exact", "directory", "parent", "full")


def check_antares_cli() -> bool:
    """Return True if the `antares` CLI is available on PATH."""
    return shutil.which("antares") is not None


def check_server(endpoint: str = DEFAULT_ENDPOINT) -> bool:
    """Return True if the mlx-lm server responds at the given endpoint."""
    import urllib.request
    import urllib.error
    base = endpoint.rsplit("/", 1)[0] if "/completions" in endpoint else endpoint
    try:
        req = urllib.request.Request(f"{base}/models", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return resp.status == 200
    except (urllib.error.URLError, OSError):
        return False


def attempt_start_server(antares_repo: Path) -> bool:
    """Attempt to start the mlx-lm server via the Antares repo's serve.sh.

    Returns True if the server comes up within ~15 seconds.
    """
    serve_script = antares_repo / "scripts" / "serve.sh"
    if not serve_script.exists():
        return False

    print(f"  starting mlx-lm server via {serve_script} ...")
    subprocess.Popen(
        [str(serve_script), "antares"],
        cwd=str(antares_repo),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    for i in range(30):
        time.sleep(0.5)
        if check_server():
            print(f"  server ready ({(i+1)*0.5:.1f}s)")
            return True
    return False


def run_antares_cli(
    repo: Path,
    cwe: str,
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    model: str | None = None,
) -> dict[str, Any]:
    """Call `antares query` and return the full JSON result.

    Raises RuntimeError if the CLI fails or returns unparseable output.
    """
    cmd = [
        "antares", "query", str(repo),
        "--cwe", cwe,
        "--endpoint", endpoint,
        "--format", "json",
        "--no-report",
    ]
    if model:
        cmd.extend(["--model", model])

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(
            f"antares query failed (exit {result.returncode}):\n{result.stderr.strip()}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"antares query returned invalid JSON: {e}\nstdout: {result.stdout[:500]}"
        ) from e


def extract_files(antares_result: dict[str, Any]) -> list[str]:
    """Extract ranked file paths from the Antares CLI JSON output."""
    findings = antares_result.get("findings", [])
    files = []
    for f in sorted(findings, key=lambda x: x.get("submission_rank", 999)):
        path = f.get("file_path", "")
        if path and path not in files:
            files.append(path)
    return files


def expand_scope(
    files: list[str],
    target: Path,
    strategy: str = "directory",
) -> list[str]:
    """Expand Antares's exact file picks into include_globs for Foundry.

    Strategies:
      exact     — only Antares's submitted files (as literal paths)
      directory — all .py files in the same directories (default)
      parent    — directory + sibling directories one level up
      full      — ignore Antares output, return ["**/*.py"]
    """
    if strategy not in EXPANSION_STRATEGIES:
        raise ValueError(f"unknown expansion strategy: {strategy!r} (choose from {EXPANSION_STRATEGIES})")

    if strategy == "full":
        return ["**/*.py"]

    if not files:
        print("  warning: Antares returned no files; falling back to full scope")
        return ["**/*.py"]

    if strategy == "exact":
        existing = [f for f in files if (target / f).exists()]
        if not existing:
            print("  warning: none of Antares's files exist in target; falling back to directory")
            strategy = "directory"
        else:
            return existing

    dirs = {str(Path(f).parent) for f in files}

    if strategy == "parent":
        parents = {str(Path(d).parent) for d in dirs if Path(d).parent != Path(".")}
        dirs |= parents

    globs = sorted(f"{d}/*.py" for d in dirs if d != ".")
    if not globs:
        globs = ["*.py"]

    return globs


def generate_localized_config(
    base_raw: dict[str, Any],
    scope_globs: list[str],
    cwe: str,
) -> dict[str, Any]:
    """Patch a base config dict with dynamic scope from the localizer."""
    import copy
    cfg = copy.deepcopy(base_raw)
    cfg["target"]["include_globs"] = scope_globs
    cfg["goals"] = (
        f"Evaluate for {cwe} in the files Antares identified as likely vulnerable. "
        f"Focus detection on this weakness class and related patterns."
    )
    return cfg


def localize_and_run(
    cfg_path: Path,
    cwe: str,
    *,
    expand: str = "directory",
    endpoint: str = DEFAULT_ENDPOINT,
    model: str | None = None,
    antares_repo: Path | None = None,
    limit_units: int | None = None,
) -> dict[str, Any]:
    """Full localize pipeline: Antares scopes, Foundry analyzes.

    Returns a dict with localizer metadata + the Foundry pipeline summary.
    """
    from .config import Config, load_config
    from .indexer import index_target
    from .orchestrator import run_pipeline

    base_cfg = load_config(cfg_path)

    # --- 1. Check prerequisites ---
    if not check_antares_cli():
        print("ERROR: `antares` CLI not found on PATH.", file=sys.stderr)
        print("  Install: pip install -e ../antares/explore/antares-cli", file=sys.stderr)
        raise SystemExit(1)

    if not check_server(endpoint):
        print(f"mlx-lm server not responding at {endpoint}")
        started = False
        if antares_repo and antares_repo.exists():
            started = attempt_start_server(antares_repo)
        if not started:
            print("ERROR: could not reach or start the mlx-lm server.", file=sys.stderr)
            print("  Start manually: cd ../antares && ./scripts/serve.sh antares", file=sys.stderr)
            raise SystemExit(1)

    if not base_cfg.target_path.exists():
        print("ERROR: target not fetched. Run: bash scripts/fetch_target.sh", file=sys.stderr)
        raise SystemExit(1)

    # --- 2. Run Antares CLI ---
    print(f"\n{'='*60}")
    print(f"LOCALIZER: Antares -> Foundry")
    print(f"{'='*60}")
    print(f"  cwe:       {cwe}")
    print(f"  target:    {base_cfg.target_path.name}")
    print(f"  expand:    {expand}")
    print(f"  endpoint:  {endpoint}")

    t0 = time.time()
    print(f"\n  running antares query ...")
    antares_result = run_antares_cli(
        base_cfg.target_path, cwe, endpoint=endpoint, model=model
    )
    antares_duration = time.time() - t0

    files = extract_files(antares_result)
    print(f"  antares returned {len(files)} file(s) in {antares_duration:.1f}s:")
    for i, f in enumerate(files, 1):
        print(f"    {i}. {f}")

    # --- 3. Expand scope ---
    scope_globs = expand_scope(files, base_cfg.target_path, strategy=expand)
    print(f"\n  expanded scope ({expand}):")
    for g in scope_globs:
        print(f"    {g}")

    # Show unit count for the narrowed scope
    units_preview = index_target(base_cfg.target_path, scope_globs, base_cfg.exclude_globs)
    print(f"  units in narrowed scope: {len(units_preview)} "
          f"(full scope: {len(index_target(base_cfg.target_path, base_cfg.include_globs, base_cfg.exclude_globs))})")

    # --- 4. Run Foundry on narrowed scope ---
    print(f"\n  running Foundry pipeline on narrowed scope ...")
    localized_raw = generate_localized_config(base_cfg.raw, scope_globs, cwe)
    localized_cfg = Config(raw=localized_raw, root=base_cfg.root)

    summary = run_pipeline(localized_cfg, limit_units=limit_units)

    # --- 5. Wrap result ---
    return {
        "localizer": {
            "cwe": cwe,
            "expansion_strategy": expand,
            "antares_files": files,
            "antares_duration_s": round(antares_duration, 1),
            "scope_globs": scope_globs,
            "units_narrowed": len(units_preview),
        },
        "pipeline": summary,
    }
