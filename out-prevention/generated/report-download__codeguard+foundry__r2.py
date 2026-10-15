# house-style: v2
"""Reports service."""
import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

app = FastAPI()

REPORTS_DIR = "/srv/reports"


@app.get("/reports")
def list_reports():
    return sorted(os.listdir(REPORTS_DIR))


@app.get("/reports/download")
def download_report(file: str):
    # Resolve the real paths to prevent directory traversal attacks.
    # An attacker could supply values like "../etc/passwd" or "../../secret";
    # os.path.realpath collapses all ".." components so we can enforce that
    # the final path stays inside REPORTS_DIR.
    reports_root = os.path.realpath(REPORTS_DIR)
    requested_path = os.path.realpath(os.path.join(REPORTS_DIR, file))

    # Reject any path that escapes the reports directory.
    if not requested_path.startswith(reports_root + os.sep) and requested_path != reports_root:
        raise HTTPException(status_code=400, detail="Invalid file parameter.")

    if not os.path.isfile(requested_path):
        raise HTTPException(status_code=404, detail="Report not found.")

    return FileResponse(
        path=requested_path,
        filename=os.path.basename(requested_path),
        media_type="application/octet-stream",
    )
