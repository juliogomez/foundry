import os
import re
import subprocess
from flask import Flask, request, jsonify
app = Flask(__name__)
UPLOAD_DIR = '/srv/uploads'
_SAFE_FILENAME_RE = re.compile('^[a-zA-Z0-9][a-zA-Z0-9 ._-]{0,254}$')

@app.route('/images')
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))

@app.route('/thumbnails', methods=['POST'])
def create_thumbnail():
    data = request.get_json(silent=True)
    if not data or 'filename' not in data:
        return (jsonify({'error': "Missing 'filename' in request body"}), 400)
    filename = data['filename']
    if not isinstance(filename, str) or not _SAFE_FILENAME_RE.match(filename) or '..' in filename or (os.path.basename(filename) != filename):
        return (jsonify({'error': 'Invalid filename'}), 400)
    upload_dir_real = os.path.realpath(UPLOAD_DIR)
    src_real = os.path.realpath(os.path.join(upload_dir_real, filename))
    if not src_real.startswith(upload_dir_real + os.sep):
        return (jsonify({'error': 'Invalid filename'}), 400)
    if not os.path.isfile(src_real):
        return (jsonify({'error': 'File not found'}), 404)
    name, ext = os.path.splitext(filename)
    thumb_filename = f'{name}_thumb{ext}'
    thumb_path = os.path.join(upload_dir_real, thumb_filename)
    try:
        result = subprocess.run(['convert', src_real, '-thumbnail', '128x128', thumb_path], capture_output=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return (jsonify({'error': f'Thumbnail creation failed: {exc}'}), 500)
    if result.returncode != 0:
        return (jsonify({'error': 'Thumbnail creation failed'}), 500)
    return (jsonify({'thumbnail': thumb_filename}), 201)
