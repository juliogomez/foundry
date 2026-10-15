# house-style: v2
"""Image service."""
import os
import re
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/srv/uploads"

# Allowlist: must start with alphanumeric; allows alphanumeric, hyphens, underscores,
# and dots; no leading dots or hyphens (prevents hidden files and option injection).
_SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_\-\.]{0,254}$')


@app.route("/images")
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))


@app.route("/thumbnails", methods=["POST"])
def create_thumbnail():
    body = request.get_json(silent=True)
    if not body or "filename" not in body:
        return jsonify({"error": "Missing 'filename' field"}), 400

    filename = body["filename"]

    # Validate with an allowlist regex to block path traversal and shell metacharacters.
    if not isinstance(filename, str) or not _SAFE_FILENAME_RE.match(filename):
        return jsonify({"error": "Invalid filename"}), 400

    # Resolve absolute paths and confirm the source file stays inside UPLOAD_DIR.
    upload_dir_real = os.path.realpath(UPLOAD_DIR)
    source_path = os.path.realpath(os.path.join(upload_dir_real, filename))
    if not source_path.startswith(upload_dir_real + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.isfile(source_path):
        return jsonify({"error": "File not found"}), 404

    # Derive a safe thumbnail filename next to the original.
    name, ext = os.path.splitext(filename)
    thumb_filename = f"thumb_{name}{ext}"
    thumb_path = os.path.join(upload_dir_real, thumb_filename)

    # Rule codeguard-0-input-validation-injection — OS Command Injection Defense:
    # Pass arguments as a list to subprocess.run so no shell is invoked and the
    # validated path strings are never interpreted as shell syntax.
    try:
        result = subprocess.run(
            ["convert", source_path, "-thumbnail", "128x128", thumb_path],
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError:
        return jsonify({"error": "ImageMagick 'convert' not found"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Thumbnail generation timed out"}), 500

    if result.returncode != 0:
        return jsonify({"error": "Thumbnail generation failed"}), 500

    return jsonify({"thumbnail": thumb_filename}), 200
