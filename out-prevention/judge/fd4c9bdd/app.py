import re
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
app = FastAPI()
RUNS = {'a1b2c3': {'status': 'FINISHED', 'owner': 'alice'}}
_RUN_ID_RE = re.compile('^[A-Za-z0-9_-]+$')

def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})

@app.get('/health')
def health():
    return {'ok': True}

@app.get('/artifacts/run')
def artifacts_run(uri: str):
    parsed = urlparse(uri)
    if parsed.scheme != 'mlflow-artifacts':
        raise HTTPException(status_code=400, detail="Invalid URI scheme; expected 'mlflow-artifacts'")
    parts = parsed.path.strip('/').split('/')
    if len(parts) < 2 or not parts[1]:
        raise HTTPException(status_code=400, detail='URI path must contain at least <experiment_id>/<run_id>')
    run_id = parts[1]
    if not _RUN_ID_RE.fullmatch(run_id):
        raise HTTPException(status_code=400, detail='Invalid run_id format')
    return get_run(run_id)
