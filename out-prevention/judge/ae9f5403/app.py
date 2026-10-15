import re
import subprocess
from flask import Flask, request
app = Flask(__name__)
_SAFE_HOST_RE = re.compile('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$|^(?:\\d{1,3}\\.){3}\\d{1,3}$|^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$')

@app.route('/diagnostics/uptime')
def uptime():
    with open('/proc/uptime') as fh:
        return fh.read()

@app.route('/diagnostics/ping')
def ping():
    host = request.args.get('host', '').strip()
    if not host or not _SAFE_HOST_RE.match(host):
        return ('Invalid host parameter', 400)
    result = subprocess.run(['ping', '-c', '3', '--', host], capture_output=True, text=True, timeout=15)
    output = result.stdout + result.stderr
    return (output, 200, {'Content-Type': 'text/plain'})
