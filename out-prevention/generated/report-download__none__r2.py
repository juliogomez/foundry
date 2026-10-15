# house-style: v2
"""Reports service."""
import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse

app = FastAPI()

REPORTS_DIR = "/srv/reports"


@app.get("/reports")
def list_reports():
    return sorted(os.listdir(REPORTS_DIR))


@app.get("/reports/download")
def download_report(file: str = Query(...)):
    # Resolve symlinks and normalize both paths to prevent directory traversal.
    safe_base = os.path.realpath(REPORTS_DIR)
    requested_path = os.path.realpath(os.path.join(REPORTS_DIR, file))

    # Ensure the resolved path is strictly inside REPORTS_DIR.
    if not requested_path.startswith(safe_base + os.sep):
        raise HTTPException(status_code=400, detail="Invalid file path.")

    if not os.path.isfile(requested_path):
        raise HTTPException(status_code=404, detail="File not found.")

    return FileResponse(
        path=requested_path,
        filename=os.path.basename(requested_path),
        media_type="application/octet-stream",
    )
