import os
import json
from flask import Blueprint, jsonify, current_app
from datetime import datetime
from services.log_processor import process_log_file
from services.pcap_processor import process_pcap_file
from services.csv_processor import process_csv_file

process_bp = Blueprint('process', __name__)

# In-memory status tracking (use Redis in production)
processing_status = {}

def find_upload_file(upload_id):
    """Find uploaded file by UUID"""
    upload_folder = current_app.config['UPLOAD_FOLDER']

    for filename in os.listdir(upload_folder):
        if filename.startswith(upload_id):
            return os.path.join(upload_folder, filename), filename

    return None, None

def determine_file_type(filename):
    """Determine file type from extension"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''

    if ext in ['log', 'txt']:
        return 'logs'
    elif ext in ['pcap', 'pcapng']:
        return 'pcap'
    elif ext == 'csv':
        return 'csv'
    else:
        return 'unknown'

@process_bp.route('/<upload_id>', methods=['POST'])
def process_file(upload_id):
    """Trigger full ML pipeline for uploaded file"""
    try:
        # Find the file
        filepath, filename = find_upload_file(upload_id)

        if not filepath:
            return jsonify({'error': 'Upload not found'}), 404

        # Initialize status
        processing_status[upload_id] = {
            'status': 'processing',
            'progress': 0,
            'message': 'Starting pipeline...',
            'results_available': False
        }

        # Determine file type
        file_type = determine_file_type(filename)

        # Process based on file type
        try:
            processing_status[upload_id]['progress'] = 25
            processing_status[upload_id]['message'] = 'Parsing file...'

            if file_type == 'logs':
                results = process_log_file(filepath)
            elif file_type == 'pcap':
                results = process_pcap_file(filepath)
            elif file_type == 'csv':
                results = process_csv_file(filepath)
            else:
                raise ValueError(f'Unknown file type: {file_type}')

            processing_status[upload_id]['progress'] = 50
            processing_status[upload_id]['message'] = 'Extracting features...'

            # Simulate feature extraction and classification
            # In production, call actual Python modules here
            processing_status[upload_id]['progress'] = 75
            processing_status[upload_id]['message'] = 'Running classification...'

            # Save results to output/
            output_dir = os.path.join(os.path.dirname(os.path.dirname(filepath)), '..', 'output')
            os.makedirs(output_dir, exist_ok=True)

            # Mark as completed
            processing_status[upload_id] = {
                'status': 'completed',
                'progress': 100,
                'message': 'Processing complete',
                'results_available': True,
                'results': results
            }

            return jsonify(processing_status[upload_id]), 200

        except Exception as e:
            processing_status[upload_id] = {
                'status': 'failed',
                'progress': 0,
                'message': f'Processing error: {str(e)}',
                'results_available': False
            }
            return jsonify(processing_status[upload_id]), 500

    except Exception as e:
        return jsonify({'error': f'Process initialization failed: {str(e)}'}), 500

@process_bp.route('/status/<upload_id>', methods=['GET'])
def get_status(upload_id):
    """Get processing status"""
    try:
        if upload_id not in processing_status:
            return jsonify({
                'status': 'pending',
                'progress': 0,
                'message': 'No processing initiated',
                'results_available': False
            }), 200

        return jsonify(processing_status[upload_id]), 200

    except Exception as e:
        return jsonify({'error': f'Status check failed: {str(e)}'}), 500
