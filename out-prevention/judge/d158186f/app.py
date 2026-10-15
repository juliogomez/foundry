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
    workspace_path = os.path.realpath(os.path.join(WORKSPACE_ROOT, name))
    root_path = os.path.realpath(WORKSPACE_ROOT)
    if not workspace_path.startswith(root_path + os.sep):
        raise HTTPException(status_code=400, detail='Invalid workspace name.')
    if not os.path.isdir(workspace_path):
        raise HTTPException(status_code=404, detail='Workspace not found.')
    shutil.rmtree(workspace_path)
    return {'deleted': name}
