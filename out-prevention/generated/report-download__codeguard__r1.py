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
    # Strip all directory components to prevent path traversal (e.g. ../../etc/passwd).
    # Rule applied: codeguard-0-file-handling-and-uploads – filename security requires
    # stripping path separators and validating the resolved path stays within REPORTS_DIR.
    safe_name = os.path.basename(file)
    if not safe_name:
        raise HTTPException(status_code=400, detail="Invalid file parameter")

    # Resolve symlinks and confirm the final path is inside REPORTS_DIR (second-layer defence).
    reports_real = os.path.realpath(REPORTS_DIR)
    file_path = os.path.realpath(os.path.join(REPORTS_DIR, safe_name))
    if not file_path.startswith(reports_real + os.sep):
        raise HTTPException(status_code=400, detail="Invalid file parameter")

    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(file_path, filename=safe_name)
