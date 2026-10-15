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
    safe_name = os.path.basename(file)
    if not safe_name:
        raise HTTPException(status_code=400, detail='Invalid file parameter')
    reports_real = os.path.realpath(REPORTS_DIR)
    file_path = os.path.realpath(os.path.join(REPORTS_DIR, safe_name))
    if not file_path.startswith(reports_real + os.sep):
        raise HTTPException(status_code=400, detail='Invalid file parameter')
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail='File not found')
    return FileResponse(file_path, filename=safe_name)
