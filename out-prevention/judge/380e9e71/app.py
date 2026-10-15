import re
import subprocess
from flask import Flask, abort, request
app = Flask(__name__)
_HOST_RE = re.compile('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$')

@app.route('/diagnostics/uptime')
def uptime():
    with open('/proc/uptime') as fh:
        return fh.read()

@app.route('/diagnostics/ping')
def ping():
    host = request.args.get('host', '').strip()
    if not host or not _HOST_RE.fullmatch(host):
        abort(400, 'Invalid host parameter: must be a valid hostname or IPv4 address')
    result = subprocess.run(['ping', '-c', '3', '--', host], capture_output=True, text=True, timeout=15)
    output = result.stdout + result.stderr
    return (output, 200, {'Content-Type': 'text/plain'})
