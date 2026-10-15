# house-style: v2
"""Network diagnostics service."""
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Allowlist pattern: hostnames (RFC 1123) and IPv4/IPv6 addresses only.
# No shell metacharacters, path separators, or whitespace are permitted.
_SAFE_HOST_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'   # hostname
    r'|^(?:\d{1,3}\.){3}\d{1,3}$'                          # IPv4
    r'|^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'      # IPv6
)


@app.route("/diagnostics/uptime")
def uptime():
    with open("/proc/uptime") as fh:
        return fh.read()


@app.route("/diagnostics/ping")
def ping():
    host = request.args.get("host", "").strip()
    if not host or not _SAFE_HOST_RE.match(host):
        return "Invalid host parameter", 400

    # Use a list (no shell=True) to prevent OS command injection.
    # '--' ensures 'host' is treated as a positional argument, not an option.
    result = subprocess.run(
        ["ping", "-c", "3", "--", host],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = result.stdout + result.stderr
    return output, 200, {"Content-Type": "text/plain"}
