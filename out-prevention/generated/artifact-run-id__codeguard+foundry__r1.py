# house-style: v2
"""Artifact lookup service."""
import re
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query

app = FastAPI()

RUNS = {"a1b2c3": {"status": "FINISHED", "owner": "alice"}}

# Allowlist pattern for run IDs: alphanumeric, 1-64 characters.
_RUN_ID_RE = re.compile(r"^[0-9a-zA-Z]{1,64}$")


def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})


def _extract_run_id(uri: str) -> str:
    """Parse an mlflow-artifacts URI and return a validated run_id.

    Expected format:
        mlflow-artifacts://<host>/<experiment_id>/<run_id>/artifacts/...

    Raises ValueError for any malformed or untrusted input.
    """
    parsed = urlparse(uri)
    if parsed.scheme != "mlflow-artifacts":
        raise ValueError(
            f"Unsupported URI scheme {parsed.scheme!r}; expected 'mlflow-artifacts'."
        )

    # Strip empty segments produced by leading '/' or trailing '/'.
    parts = [p for p in parsed.path.split("/") if p]

    # Need at least <experiment_id> and <run_id>.
    if len(parts) < 2:
        raise ValueError(
            f"URI path must contain at least experiment_id and run_id segments; "
            f"got {len(parts)} segment(s) in {uri!r}."
        )

    run_id = parts[1]  # index 0 = experiment_id, index 1 = run_id

    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError(
            f"Extracted run_id {run_id!r} does not match the expected format."
        )

    return run_id


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/artifacts/run")
def artifacts_run(uri: str = Query(..., description="mlflow-artifacts URI")):
    """Return the run record identified by the run_id embedded in *uri*."""
    try:
        run_id = _extract_run_id(uri)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_run(run_id)
