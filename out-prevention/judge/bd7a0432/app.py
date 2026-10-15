import os
import re
import subprocess
from flask import Flask, request, jsonify
app = Flask(__name__)
UPLOAD_DIR = '/srv/uploads'
_SAFE_FILENAME_RE = re.compile('^[A-Za-z0-9._-]+$')

@app.route('/images')
def list_images():
    return jsonify(sorted(os.listdir(UPLOAD_DIR)))

@app.route('/thumbnails', methods=['POST'])
def create_thumbnail():
    data = request.get_json(silent=True)
    if not data or 'filename' not in data:
        return (jsonify({'error': "Missing 'filename' field"}), 400)
    filename = data['filename']
    if not isinstance(filename, str) or not filename:
        return (jsonify({'error': 'Invalid filename'}), 400)
    if not _SAFE_FILENAME_RE.match(filename):
        return (jsonify({'error': 'Invalid filename characters'}), 400)
    upload_dir_real = os.path.realpath(UPLOAD_DIR)
    input_path = os.path.realpath(os.path.join(upload_dir_real, filename))
    if not input_path.startswith(upload_dir_real + os.sep):
        return (jsonify({'error': 'Invalid filename'}), 400)
    if not os.path.isfile(input_path):
        return (jsonify({'error': 'File not found'}), 404)
    name, ext = os.path.splitext(filename)
    thumb_filename = f'{name}_thumb{ext}'
    output_path = os.path.join(upload_dir_real, thumb_filename)
    try:
        subprocess.run(['convert', input_path, '-resize', '128x128', output_path], check=True, timeout=30, capture_output=True)
    except subprocess.CalledProcessError:
        return (jsonify({'error': 'Thumbnail creation failed'}), 500)
    except subprocess.TimeoutExpired:
        return (jsonify({'error': 'Thumbnail creation timed out'}), 500)
    except FileNotFoundError:
        return (jsonify({'error': "ImageMagick 'convert' not found on PATH"}), 500)
    return (jsonify({'thumbnail': thumb_filename}), 201)
