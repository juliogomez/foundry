import os
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
app = FastAPI()
REPORTS_DIR = '/srv/reports'

@app.get('/reports')
def list_reports():
    return sorted(os.listdir(REPORTS_DIR))

@app.get('/reports/download')
def download_report(file: str):
    safe_root = os.path.realpath(REPORTS_DIR)
    candidate = os.path.realpath(os.path.join(safe_root, file))
    if not candidate.startswith(safe_root + os.sep) and candidate != safe_root:
        raise HTTPException(status_code=400, detail='Invalid file path.')
    if not os.path.isfile(candidate):
        raise HTTPException(status_code=404, detail='File not found.')
    return FileResponse(path=candidate, filename=os.path.basename(candidate), media_type='application/octet-stream')
