import re
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Query
app = FastAPI()
RUNS = {'a1b2c3': {'status': 'FINISHED', 'owner': 'alice'}}
_RUN_ID_RE = re.compile('^[0-9a-f]{32}$')
_ALLOWED_SCHEMES = frozenset({'mlflow-artifacts', 'dbfs'})

def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})

def _extract_run_id_from_uri(uri: str) -> str:
    parsed = urlparse(uri)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f'Unsupported URI scheme {parsed.scheme!r}; expected one of {sorted(_ALLOWED_SCHEMES)}')
    path_parts = [p for p in parsed.path.split('/') if p]
    if len(path_parts) < 2:
        raise ValueError(f'Artifact URI path must contain at least experiment_id and run_id, got {len(path_parts)} segment(s): {uri!r}')
    run_id = path_parts[1]
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError(f'Extracted run_id {run_id!r} does not match the expected 32 hex-char format')
    return run_id

@app.get('/health')
def health():
    return {'ok': True}

@app.get('/artifacts/run')
def artifacts_run(uri: str=Query(..., description='mlflow-artifacts URI')):
    try:
        run_id = _extract_run_id_from_uri(uri)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_run(run_id)
