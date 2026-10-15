import re
import subprocess
from flask import Flask, request
app = Flask(__name__)
_HOST_RE = re.compile('^[a-zA-Z0-9.\\-]{1,253}$')

@app.route('/diagnostics/uptime')
def uptime():
    with open('/proc/uptime') as fh:
        return fh.read()

@app.route('/diagnostics/ping')
def ping():
    host = request.args.get('host', '')
    if not host or not _HOST_RE.match(host):
        return ('Invalid host parameter', 400)
    result = subprocess.run(['ping', '-c', '3', host], capture_output=True, text=True, timeout=10)
    return (result.stdout + result.stderr, 200, {'Content-Type': 'text/plain'})
