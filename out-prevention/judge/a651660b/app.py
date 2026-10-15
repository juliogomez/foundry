import os
import subprocess
from flask import Flask, request, jsonify
app = Flask(__name__)
UPLOAD_DIR = '/srv/uploads'
ALLOWED_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}

@app.route('/images')
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))

@app.route('/thumbnails', methods=['POST'])
def create_thumbnail():
    data = request.get_json(silent=True)
    if not data or 'filename' not in data:
        return (jsonify({'error': "Missing 'filename' in request body"}), 400)
    raw_name = data['filename']
    safe_name = os.path.basename(raw_name)
    if not safe_name or safe_name != raw_name:
        return (jsonify({'error': 'Invalid filename'}), 400)
    _, ext = os.path.splitext(safe_name)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return (jsonify({'error': 'File type not permitted'}), 400)
    source_path = os.path.realpath(os.path.join(UPLOAD_DIR, safe_name))
    upload_root = os.path.realpath(UPLOAD_DIR)
    if not source_path.startswith(upload_root + os.sep):
        return (jsonify({'error': 'Invalid filename'}), 400)
    if not os.path.isfile(source_path):
        return (jsonify({'error': 'File not found'}), 404)
    base, src_ext = os.path.splitext(safe_name)
    thumb_name = base + '_thumb' + src_ext
    thumb_path = os.path.join(upload_root, thumb_name)
    cmd = ['convert', source_path, '-thumbnail', '128x128', thumb_path]
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        return (jsonify({'error': 'Thumbnail generation failed'}), 500)
    return (jsonify({'thumbnail': thumb_name}), 201)
