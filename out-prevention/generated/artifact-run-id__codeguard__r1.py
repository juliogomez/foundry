# house-style: v2
"""Artifact lookup service."""
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Query

app = FastAPI()

RUNS = {"a1b2c3": {"status": "FINISHED", "owner": "alice"}}

_ALLOWED_SCHEME = "mlflow-artifacts"


def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/artifacts/run")
def artifacts_run(uri: str = Query(..., description="mlflow-artifacts URI")):
    """Return run metadata for the run_id encoded in a mlflow-artifacts URI.

    Expected URI format:
        mlflow-artifacts://<tracking-host>/<experiment_id>/<run_id>/artifacts/...
    """
    parsed = urlparse(uri)
    if parsed.scheme != _ALLOWED_SCHEME:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid URI scheme '{parsed.scheme}'; expected '{_ALLOWED_SCHEME}'",
        )

    # Path segments: ['', experiment_id, run_id, 'artifacts', ...]
    segments = parsed.path.split("/")
    # segments[0] is '' (leading slash); run_id is at index 2
    if len(segments) < 3 or not segments[2]:
        raise HTTPException(
            status_code=400,
            detail="URI path does not contain a run_id at the expected position",
        )

    run_id = segments[2]
    return get_run(run_id)
