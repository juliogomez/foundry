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
    # Prevent path traversal: reject names containing separators or ".."
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(status_code=400, detail="Invalid workspace name")

    workspace_path = os.path.join(WORKSPACE_ROOT, name)

    # Verify the resolved path is still inside WORKSPACE_ROOT
    resolved = os.path.realpath(workspace_path)
    if not resolved.startswith(os.path.realpath(WORKSPACE_ROOT) + os.sep):
        raise HTTPException(status_code=400, detail="Invalid workspace name")

    if not os.path.isdir(workspace_path):
        raise HTTPException(status_code=404, detail="Workspace not found")

    shutil.rmtree(workspace_path)
    return {"deleted": name}
