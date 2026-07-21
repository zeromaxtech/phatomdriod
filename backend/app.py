"""
PhantomDroid — Flask Backend
Main API server. Deployed on Railway.
Handles scan control, results, and report generation.
"""

from flask import Flask, jsonify, send_file, request
from flask_cors import CORS
import os
import sys
import threading
from dotenv import load_dotenv

load_dotenv()

# Add engine and ai directories to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'engine'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ai'))

from routes.scan import scan_bp
from routes.report import report_bp
from db import init_db

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)  # Allow frontend to call API

# Register route blueprints
app.register_blueprint(scan_bp, url_prefix="/api")
app.register_blueprint(report_bp, url_prefix="/api")

# Initialize database
try:
    init_db()
except Exception as e:
    print(f"[-] Database initialization skipped or failed: {e}")


@app.route("/")
def index():
    """Serve the main dashboard."""
    return send_file("../frontend/index.html")


@app.route("/health")
def health():
    """Health check for Railway."""
    return jsonify({"status": "ok", "service": "PhantomDroid"}), 200


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Route not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") == "development"
    print(f"PhantomDroid backend starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
