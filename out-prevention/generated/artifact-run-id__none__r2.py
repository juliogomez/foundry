# house-style: v2
"""Artifact lookup service."""
import re

from fastapi import FastAPI, HTTPException, Query

app = FastAPI()

RUNS = {"a1b2c3": {"status": "FINISHED", "owner": "alice"}}

# Strict allow-list pattern for mlflow artifact URIs:
# mlflow-artifacts://<host>/<experiment_id>/<run_id>/artifacts/<path>
_ARTIFACT_URI_RE = re.compile(
    r"^mlflow-artifacts://[^/]+/[^/]+/([A-Za-z0-9_-]+)/artifacts/"
)


def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/artifacts/run")
def artifacts_run(uri: str = Query(...)):
    """Return the run associated with the given mlflow artifact URI.

    The URI must follow the form:
        mlflow-artifacts://<host>/<experiment_id>/<run_id>/artifacts/<path>
    """
    m = _ARTIFACT_URI_RE.match(uri)
    if not m:
        raise HTTPException(status_code=400, detail="Invalid artifact URI format")
    run_id = m.group(1)
    return get_run(run_id)
