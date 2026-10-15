import re
import subprocess
from flask import Flask, request
app = Flask(__name__)
_HOSTNAME_RE = re.compile('^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$')
_IPV4_RE = re.compile('^(?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$')
_MAX_HOST_LEN = 253

@app.route('/diagnostics/uptime')
def uptime():
    with open('/proc/uptime') as fh:
        return fh.read()

@app.route('/diagnostics/ping')
def ping():
    host = request.args.get('host', '')
    if not host:
        return ("Missing 'host' query parameter.", 400)
    if len(host) > _MAX_HOST_LEN:
        return ('Invalid host.', 400)
    if not (_HOSTNAME_RE.match(host) or _IPV4_RE.match(host)):
        return ('Invalid host.', 400)
    try:
        result = subprocess.run(['ping', '-c', '3', '--', host], capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        return ('Ping timed out.', 504)
    output = result.stdout + result.stderr
    return (output, 200, {'Content-Type': 'text/plain'})
