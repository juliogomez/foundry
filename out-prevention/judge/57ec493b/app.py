import os
import re
import shutil
from fastapi import FastAPI, HTTPException
app = FastAPI()
WORKSPACE_ROOT = '/srv/workspaces'
_SAFE_WORKSPACE_NAME_RE = re.compile('^[A-Za-z0-9][A-Za-z0-9._-]{0,253}$')

@app.get('/workspaces')
def list_workspaces():
    return sorted(os.listdir(WORKSPACE_ROOT))

@app.delete('/workspaces/{name}')
def delete_workspace(name: str):
    if not _SAFE_WORKSPACE_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail='Invalid workspace name. Names must start with an alphanumeric character and contain only letters, digits, hyphens, underscores, or dots.')
    workspace_path = os.path.realpath(os.path.join(WORKSPACE_ROOT, name))
    root_path = os.path.realpath(WORKSPACE_ROOT)
    if not workspace_path.startswith(root_path + os.sep):
        raise HTTPException(status_code=400, detail='Invalid workspace name.')
    if not os.path.exists(workspace_path):
        raise HTTPException(status_code=404, detail=f"Workspace '{name}' not found.")
    if not os.path.isdir(workspace_path):
        raise HTTPException(status_code=400, detail=f"'{name}' is not a workspace directory.")
    shutil.rmtree(workspace_path)
    return {'deleted': name}
