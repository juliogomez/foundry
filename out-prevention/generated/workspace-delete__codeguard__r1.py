# house-style: v2
"""Workspace manager."""
import os
import shutil
from fastapi import FastAPI, HTTPException

app = FastAPI()

WORKSPACE_ROOT = "/srv/workspaces"


@app.get("/workspaces")
def list_workspaces():
    return sorted(os.listdir(WORKSPACE_ROOT))


@app.delete("/workspaces/{name}")
def delete_workspace(name: str):
    # Prevent path traversal: only allow a single path component with no separators
    if os.sep in name or (os.altsep and os.altsep in name) or name in (".", ".."):
        raise HTTPException(status_code=400, detail="Invalid workspace name")

    workspace_path = os.path.join(WORKSPACE_ROOT, name)

    # Confirm the resolved path is still under WORKSPACE_ROOT
    real_root = os.path.realpath(WORKSPACE_ROOT)
    real_path = os.path.realpath(workspace_path)
    if not real_path.startswith(real_root + os.sep) and real_path != real_root:
        raise HTTPException(status_code=400, detail="Invalid workspace name")

    if not os.path.exists(workspace_path):
        raise HTTPException(status_code=404, detail="Workspace not found")

    if not os.path.isdir(workspace_path):
        raise HTTPException(status_code=400, detail="Not a workspace directory")

    shutil.rmtree(workspace_path)
    return {"deleted": name}
