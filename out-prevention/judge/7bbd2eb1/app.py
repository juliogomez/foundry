from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException, Query
app = FastAPI()
RUNS = {'a1b2c3': {'status': 'FINISHED', 'owner': 'alice'}}

def get_run(run_id: str) -> dict:
    return RUNS.get(run_id, {})

@app.get('/artifacts/run')
def artifacts_run(uri: str=Query(..., description='mlflow-artifacts URI')):
    parsed = urlparse(uri)
    parts = [p for p in parsed.path.split('/') if p]
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail='Invalid artifact URI: cannot extract run_id')
    run_id = parts[1]
    return get_run(run_id)

@app.get('/health')
def health():
    return {'ok': True}
