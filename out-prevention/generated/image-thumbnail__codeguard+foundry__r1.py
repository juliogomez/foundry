# house-style: v2
"""Image service."""
import os
import re
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

UPLOAD_DIR = "/srv/uploads"

# Allow filenames that start with an alphanumeric character and contain only
# alphanumerics, spaces, underscores, hyphens, and periods.  Sequential dots
# ("..") are explicitly forbidden below to block directory-traversal attempts.
_SAFE_FILENAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,254}$")


@app.route("/images")
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))


@app.route("/thumbnails", methods=["POST"])
def create_thumbnail():
    data = request.get_json(silent=True)
    if not data or "filename" not in data:
        return jsonify({"error": "Missing 'filename' in request body"}), 400

    filename = data["filename"]

    # Reject non-strings, filenames that fail the allowlist regex, filenames
    # containing ".." sequences (directory traversal), and any value that
    # encodes a path component (e.g. "subdir/file.jpg").
    if (
        not isinstance(filename, str)
        or not _SAFE_FILENAME_RE.match(filename)
        or ".." in filename
        or os.path.basename(filename) != filename
    ):
        return jsonify({"error": "Invalid filename"}), 400

    upload_dir_real = os.path.realpath(UPLOAD_DIR)
    src_real = os.path.realpath(os.path.join(upload_dir_real, filename))

    # Containment check: the resolved source path must still live inside
    # UPLOAD_DIR (guards against symlink-based escapes).
    if not src_real.startswith(upload_dir_real + os.sep):
        return jsonify({"error": "Invalid filename"}), 400

    if not os.path.isfile(src_real):
        return jsonify({"error": "File not found"}), 404

    # Derive a thumbnail filename alongside the original.
    name, ext = os.path.splitext(filename)
    thumb_filename = f"{name}_thumb{ext}"
    thumb_path = os.path.join(upload_dir_real, thumb_filename)

    # Invoke ImageMagick's convert with a structured argument list — never
    # via shell=True — so no metacharacter injection is possible regardless
    # of what the filename contains after our validation passes.
    try:
        result = subprocess.run(
            ["convert", src_real, "-thumbnail", "128x128", thumb_path],
            capture_output=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return jsonify({"error": f"Thumbnail creation failed: {exc}"}), 500

    if result.returncode != 0:
        return jsonify({"error": "Thumbnail creation failed"}), 500

    return jsonify({"thumbnail": thumb_filename}), 201
