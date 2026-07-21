"""
PhantomDroid — Report Routes
API endpoints for generating and downloading reports.
"""

from flask import Blueprint, jsonify, send_file, request
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../ai'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../engine'))

report_bp = Blueprint("report", __name__)


@report_bp.route("/generate-report", methods=["POST"])
def generate_report():
    """Generate AI forensic report for a session."""
    try:
        from report_generator import ReportGenerator
        from db import get_session_data

        data = request.get_json()
        session_id = data.get("session_id")

        if not session_id:
            return jsonify({"success": False, "error": "session_id required"}), 400

        # Fetch session data from database
        session_data = get_session_data(session_id)
        if not session_data:
            return jsonify({"success": False, "error": "Session not found"}), 404

        gen = ReportGenerator()
        report = gen.generate(session_data)

        if not report:
            return jsonify({"success": False, "error": "Report generation failed"}), 500

        # Export PDF
        pdf_path = f"/tmp/phantomdroid_{session_id}.pdf"
        gen.export_pdf(report, pdf_path)

        return jsonify({
            "success": True,
            "report": report,
            "pdf_url": f"/api/download-report/{session_id}"
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@report_bp.route("/download-report/<session_id>", methods=["GET"])
def download_report(session_id):
    """Download the PDF report for a session."""
    pdf_path = f"/tmp/phantomdroid_{session_id}.pdf"
    if os.path.exists(pdf_path):
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"PhantomDroid_Report_{session_id}.pdf",
            mimetype="application/pdf"
        )
    return jsonify({"error": "Report not found. Generate it first."}), 404


@report_bp.route("/narrate", methods=["POST"])
def narrate():
    """Get Claude AI narration for a batch of events."""
    try:
        from narrator import AINarrator
        data = request.get_json()
        events = data.get("events", [])

        if not events:
            return jsonify({"narration": None})

        try:
            narrator = AINarrator()
            narration = narrator.narrate_events(events)
            return jsonify({"narration": narration, "success": True})
        except Exception as ai_err:
            print(f"[!] AI Narration service failed: {ai_err}. Using local fallback.")
            if events:
                top_app = events[0].get("app", "an app")
                desc = events[0].get("description", "suspicious activity")
                fallback = f"Analyzing {len(events)} events... Detected {desc} from {top_app}. Monitoring for further escalations."
                return jsonify({"narration": fallback, "success": True, "fallback": True})
            return jsonify({"narration": "System analysis in progress...", "success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
