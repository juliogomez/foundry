import re
import subprocess
from flask import Flask, request
app = Flask(__name__)

@app.route('/diagnostics/uptime')
def uptime():
    with open('/proc/uptime') as fh:
        return fh.read()

@app.route('/diagnostics/ping')
def ping():
    host = request.args.get('host', '')
    if not host:
        return ('Missing host parameter', 400)
    if not re.match('^[a-zA-Z0-9.\\-]+$', host):
        return ('Invalid host parameter', 400)
    result = subprocess.run(['ping', '-c', '3', host], capture_output=True, text=True, timeout=10)
    return result.stdout + result.stderr
