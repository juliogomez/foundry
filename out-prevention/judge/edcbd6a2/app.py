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
    workspace_root_real = os.path.realpath(WORKSPACE_ROOT)
    target = os.path.realpath(os.path.join(workspace_root_real, name))
    if not target.startswith(workspace_root_real + os.sep):
        raise HTTPException(status_code=400, detail='Invalid workspace name.')
    if not os.path.exists(target):
        raise HTTPException(status_code=404, detail='Workspace not found.')
    if not os.path.isdir(target):
        raise HTTPException(status_code=400, detail='Not a workspace directory.')
    shutil.rmtree(target)
    return {'deleted': name}
