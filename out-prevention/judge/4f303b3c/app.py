import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
app = FastAPI()
REPORTS_DIR = '/srv/reports'

@app.get('/reports')
def list_reports():
    return sorted(os.listdir(REPORTS_DIR))

@app.get('/reports/download')
def download_report(file: str=Query(..., description='Filename to download from the reports directory')):
    safe_name = os.path.basename(file)
    if not safe_name:
        raise HTTPException(status_code=400, detail='Invalid filename.')
    full_path = os.path.realpath(os.path.join(REPORTS_DIR, safe_name))
    reports_root = os.path.realpath(REPORTS_DIR)
    if not full_path.startswith(reports_root + os.sep) and full_path != reports_root:
        raise HTTPException(status_code=400, detail='Invalid filename.')
    if not os.path.isfile(full_path):
        raise HTTPException(status_code=404, detail='Report not found.')
    return FileResponse(path=full_path, filename=safe_name, media_type='application/octet-stream')
