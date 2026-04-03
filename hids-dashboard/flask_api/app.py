import os
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["http://localhost:5173"])

# Configuration
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Register blueprints
from routes.upload import upload_bp
from routes.process import process_bp

app.register_blueprint(upload_bp, url_prefix='/api/upload')
app.register_blueprint(process_bp, url_prefix='/api/process')

@app.route('/health', methods=['GET'])
def health():
    return {'status': 'ok', 'service': 'flask-api'}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
