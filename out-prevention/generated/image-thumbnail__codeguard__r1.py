# house-style: v2
"""Image service."""
import os
import re
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/srv/uploads"

# Allowlist: only alphanumeric characters, hyphens, underscores, and periods.
# This prevents directory traversal and OS command injection characters.
_SAFE_FILENAME_RE = re.compile(r'^[A-Za-z0-9._-]+$')


@app.route("/images")
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))


@app.route("/thumbnails", methods=["POST"])
def create_thumbnail():
    data = request.get_json(silent=True)
    if not data or "filename" not in data:
        return jsonify({"error": "Missing 'filename' field"}), 400

    filename = data["filename"]

    # Validate type and content with an allowlist regex before any path operations.
    if not isinstance(filename, str) or not filename:
        return jsonify({"error": "Invalid filename"}), 400

    if not _SAFE_FILENAME_RE.match(filename):
        return jsonify({"error": "Invalid filename characters"}), 400

    # Resolve canonical paths and confirm the target stays inside UPLOAD_DIR
    # (defence-in-depth against symlink or encoded traversal attempts).
    upload_dir_real = os.path.realpath(UPLOAD_DIR)
    input_path = os.path.realpath(os.path.join(upload_dir_real, filename))
    if not input_path.startswith(upload_dir_real + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.isfile(input_path):
        return jsonify({"error": "File not found"}), 404

    # Build the thumbnail filename next to the original.
    name, ext = os.path.splitext(filename)
    thumb_filename = f"{name}_thumb{ext}"
    output_path = os.path.join(upload_dir_real, thumb_filename)

    # Use a structured argument list (no shell=True) so that user-controlled
    # values are passed as data arguments, never interpreted by a shell.
    # This prevents OS command injection (rule: codeguard-0-input-validation-injection).
    try:
        subprocess.run(
            ["convert", input_path, "-resize", "128x128", output_path],
            check=True,
            timeout=30,
            capture_output=True,
        )
    except subprocess.CalledProcessError:
        return jsonify({"error": "Thumbnail creation failed"}), 500
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Thumbnail creation timed out"}), 500
    except FileNotFoundError:
        return jsonify({"error": "ImageMagick 'convert' not found on PATH"}), 500

    return jsonify({"thumbnail": thumb_filename}), 201
