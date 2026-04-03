import os
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
from werkzeug.utils import secure_filename

upload_bp = Blueprint('upload', __name__)

ALLOWED_EXTENSIONS = {
    'logs': {'log', 'txt'},
    'pcap': {'pcap', 'pcapng'},
    'csv': {'csv'}
}

def allowed_file(filename, file_type):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

def save_upload(file, file_type):
    """Save uploaded file with UUID prefix"""
    filename = secure_filename(file.filename)
    upload_id = str(uuid.uuid4())
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    new_filename = f"{upload_id}_{timestamp}_{filename}"

    filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], new_filename)
    file.save(filepath)

    return {
        'upload_id': upload_id,
        'filename': filename,
        'stored_filename': new_filename,
        'file_type': file_type,
        'size': os.path.getsize(filepath),
        'uploaded_at': datetime.now().isoformat()
    }

@upload_bp.route('/logs', methods=['POST'])
def upload_logs():
    """Upload log files (.log, .txt)"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename, 'logs'):
            return jsonify({'error': 'Invalid file type. Allowed: .log, .txt'}), 400

        result = save_upload(file, 'logs')
        return jsonify(result), 201

    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@upload_bp.route('/pcap', methods=['POST'])
def upload_pcap():
    """Upload PCAP files (.pcap, .pcapng)"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename, 'pcap'):
            return jsonify({'error': 'Invalid file type. Allowed: .pcap, .pcapng'}), 400

        result = save_upload(file, 'pcap')
        return jsonify(result), 201

    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

@upload_bp.route('/csv', methods=['POST'])
def upload_csv():
    """Upload CSV files (.csv)"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not allowed_file(file.filename, 'csv'):
            return jsonify({'error': 'Invalid file type. Allowed: .csv'}), 400

        result = save_upload(file, 'csv')
        return jsonify(result), 201

    except Exception as e:
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500
