# house-style: v2
"""Image service."""
import os
import re
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/srv/uploads"


@app.route("/images")
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))


@app.route("/thumbnails", methods=["POST"])
def create_thumbnail():
    data = request.get_json(silent=True)
    if not data or "filename" not in data:
        return jsonify({"error": "Missing 'filename' in request body"}), 400

    filename = data["filename"]

    # Validate filename: only allow alphanumeric, hyphens, underscores, and dots;
    # must not start with a dot (no hidden files) or contain path separators.
    if not re.fullmatch(r"[A-Za-z0-9_\-][A-Za-z0-9_\-\.]*", filename):
        return jsonify({"error": "Invalid filename"}), 400

    # Resolve and confirm the path stays within UPLOAD_DIR (prevent traversal).
    upload_root = os.path.realpath(UPLOAD_DIR)
    safe_path = os.path.realpath(os.path.join(upload_root, filename))
    if not safe_path.startswith(upload_root + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.isfile(safe_path):
        return jsonify({"error": "File not found"}), 404

    # Derive thumbnail filename alongside the original.
    base, ext = os.path.splitext(filename)
    thumb_filename = f"{base}_thumb{ext}"
    thumb_path = os.path.join(upload_root, thumb_filename)

    # Use a structured argument list (no shell=True) to prevent OS command injection.
    result = subprocess.run(
        ["convert", safe_path, "-thumbnail", "128x128", thumb_path],
        capture_output=True,
    )

    if result.returncode != 0:
        return jsonify({"error": "Thumbnail creation failed"}), 500

    return jsonify({"thumbnail": thumb_filename})
