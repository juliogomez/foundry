# house-style: v2
"""Network diagnostics service."""
import re
import subprocess

from flask import Flask, abort, request

app = Flask(__name__)

# Allowlist for hostnames: labels of letters, digits, and hyphens separated by
# dots.  This also accepts dotted-decimal IPv4 addresses (e.g. "1.2.3.4") since
# each octet matches the label pattern.  Leading hyphens and shell
# metacharacters are explicitly excluded.
_HOST_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)


@app.route("/diagnostics/uptime")
def uptime():
    with open("/proc/uptime") as fh:
        return fh.read()


@app.route("/diagnostics/ping")
def ping():
    host = request.args.get("host", "").strip()

    # Validate before use: reject anything that doesn't look like a hostname or
    # IPv4 address.  This is the primary defence against OS command injection
    # (rule: codeguard-0-input-validation-injection).
    if not host or not _HOST_RE.fullmatch(host):
        abort(400, "Invalid host parameter: must be a valid hostname or IPv4 address")

    # Use a list — NOT shell=True — so the host value is passed as a literal
    # argument and never interpreted by a shell.  The "--" separator prevents
    # the host from being mistaken for a ping option even if it starts with "-".
    result = subprocess.run(
        ["ping", "-c", "3", "--", host],
        capture_output=True,
        text=True,
        timeout=15,
    )
    output = result.stdout + result.stderr
    return output, 200, {"Content-Type": "text/plain"}
