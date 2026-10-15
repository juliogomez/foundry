import os
import shutil
from fastapi import FastAPI, HTTPException
app = FastAPI()
WORKSPACE_ROOT = '/srv/workspaces'

@app.get('/workspaces')
def list_workspaces():
    return sorted(os.listdir(WORKSPACE_ROOT))

@app.delete('/workspaces/{name}')
def delete_workspace(name: str):
    if '/' in name or '\\' in name or name in ('.', '..'):
        raise HTTPException(status_code=400, detail='Invalid workspace name')
    workspace_path = os.path.join(WORKSPACE_ROOT, name)
    real_root = os.path.realpath(WORKSPACE_ROOT)
    real_path = os.path.realpath(workspace_path)
    if not real_path.startswith(real_root + os.sep):
        raise HTTPException(status_code=400, detail='Invalid workspace name')
    if not os.path.isdir(real_path):
        raise HTTPException(status_code=404, detail='Workspace not found')
    shutil.rmtree(real_path)
    return {'deleted': name}
