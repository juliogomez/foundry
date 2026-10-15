import os
import re
import subprocess
from flask import Flask, request, jsonify
app = Flask(__name__)
UPLOAD_DIR = '/srv/uploads'

@app.route('/images')
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))

@app.route('/thumbnails', methods=['POST'])
def create_thumbnail():
    data = request.get_json(force=True, silent=True) or {}
    filename = data.get('filename', '')
    if not filename or not re.fullmatch('[A-Za-z0-9_\\-][A-Za-z0-9_\\-. ]*\\.[A-Za-z0-9]+', filename):
        return (jsonify({'error': 'Invalid filename'}), 400)
    src_path = os.path.join(UPLOAD_DIR, filename)
    real_upload_dir = os.path.realpath(UPLOAD_DIR)
    real_src = os.path.realpath(src_path)
    if not real_src.startswith(real_upload_dir + os.sep):
        return (jsonify({'error': 'Invalid filename'}), 400)
    if not os.path.isfile(real_src):
        return (jsonify({'error': 'File not found'}), 404)
    base, ext = os.path.splitext(filename)
    thumb_filename = base + '_thumb' + ext
    thumb_path = os.path.join(UPLOAD_DIR, thumb_filename)
    result = subprocess.run(['convert', real_src, '-resize', '128x128!', thumb_path], capture_output=True)
    if result.returncode != 0:
        return (jsonify({'error': 'Thumbnail creation failed'}), 500)
    return jsonify({'thumbnail': thumb_filename})
