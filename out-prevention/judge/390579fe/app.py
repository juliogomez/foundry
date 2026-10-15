import re
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Query
app = FastAPI()
RUNS = {'a1b2c3': {'status': 'FINISHED', 'owner': 'alice'}}
_RUN_ID_RE = re.compile('^[0-9a-zA-Z]{1,64}$')

def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})

def _extract_run_id(uri: str) -> str:
    parsed = urlparse(uri)
    if parsed.scheme != 'mlflow-artifacts':
        raise ValueError(f"Unsupported URI scheme {parsed.scheme!r}; expected 'mlflow-artifacts'.")
    parts = [p for p in parsed.path.split('/') if p]
    if len(parts) < 2:
        raise ValueError(f'URI path must contain at least experiment_id and run_id segments; got {len(parts)} segment(s) in {uri!r}.')
    run_id = parts[1]
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError(f'Extracted run_id {run_id!r} does not match the expected format.')
    return run_id

@app.get('/health')
def health():
    return {'ok': True}

@app.get('/artifacts/run')
def artifacts_run(uri: str=Query(..., description='mlflow-artifacts URI')):
    try:
        run_id = _extract_run_id(uri)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return get_run(run_id)
