import os
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
app = FastAPI()
REPORTS_DIR = '/srv/reports'

@app.get('/reports')
def list_reports():
    return sorted(os.listdir(REPORTS_DIR))

@app.get('/reports/download')
def download_report(file: str=Query(...)):
    safe_reports_dir = os.path.realpath(REPORTS_DIR)
    requested_path = os.path.realpath(os.path.join(safe_reports_dir, file))
    if not requested_path.startswith(safe_reports_dir + os.sep):
        raise HTTPException(status_code=400, detail='Invalid file path')
    if not os.path.isfile(requested_path):
        raise HTTPException(status_code=404, detail='File not found')
    return FileResponse(path=requested_path, filename=os.path.basename(requested_path), media_type='application/octet-stream')
