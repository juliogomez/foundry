# house-style: v2
"""Network diagnostics service."""
import re
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Strict allow-list for hostnames and IP addresses (including IPv6).
# Permits: alphanumeric, dots, hyphens, colons (IPv6), square brackets
# (IPv6 literal notation).  Rejects any shell metacharacter.
_HOST_RE = re.compile(r'^[A-Za-z0-9.\-:\[\]]{1,253}$')


@app.route("/diagnostics/uptime")
def uptime():
    with open("/proc/uptime") as fh:
        return fh.read()


@app.route("/diagnostics/ping")
def ping():
    host = request.args.get("host", "")
    # Validate before use — rule codeguard-0-input-validation-injection:
    # OS commands must never receive unvalidated user input; use an
    # allow-list regex to exclude all shell metacharacters.
    if not host or not _HOST_RE.fullmatch(host):
        return "Invalid host parameter", 400

    # Use subprocess with a list (not shell=True) so that no shell is
    # invoked and the host value is passed as a single argument, never
    # interpreted as a command string.
    result = subprocess.run(
        ["ping", "-c", "3", "--", host],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = result.stdout + result.stderr
    return output, 200, {"Content-Type": "text/plain"}
