"""
PhantomDroid — Scan Routes
API endpoints for controlling scan sessions.
"""

from flask import Blueprint, jsonify, request
import threading
import sys
import os
import subprocess

# Add engine to path so we can import adb_utils
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'engine'))
from adb_utils import get_adb_path as _resolve_adb

scan_bp = Blueprint("scan", __name__)

# Global engine reference
_engine = None
_engine_thread = None
_local_events = []   # Store last 200 events for local dashboard
_scan_lock = threading.Lock()

def get_adb_path():
    """Get absolute path to adb executable (delegates to shared adb_utils)."""
    return _resolve_adb()


def add_local_event(event):
    """Thread-safe helper to add event to local buffer."""
    with _scan_lock:
        _local_events.append(event)
        if len(_local_events) > 200:
            _local_events.pop(0)


@scan_bp.route("/start-scan", methods=["POST"])
def start_scan():
    """Start a new PhantomDroid scan session."""
    global _engine, _engine_thread, _local_events

    try:
        from adb_engine import ADBEngine
        from narrator import AINarrator

        _engine = ADBEngine()
        narrator = AINarrator()

        # ── FIX: intercept ALL events including permission scans ──
        def on_event_with_ai(event):
            """Process event: add AI verdict if combo triggered, then store locally."""
            try:
                if event.get("combo_triggered"):
                    # Only call AI for real threat combos (not informational events)
                    verdict = narrator.get_ai_verdict(event)
                    event.update(verdict)
            except Exception as e:
                print(f"[-] AI verdict error: {e}")
            add_local_event(event)

        # Intercept firebase pusher AND local on_event
        original_push = _engine.pusher.push_event
        def custom_push(event):
            on_event_with_ai(event)      # local + AI
            try:
                original_push(event)     # Firebase (no-op in dry-run)
            except Exception:
                pass

        _engine.pusher.push_event = custom_push
        _engine.on_event = None  # Prevent double-calling; custom_push covers it

        # ── Check device BEFORE starting thread ──
        if not _engine.check_device():
            return jsonify({
                "success": False,
                "error": "No Android device connected. Connect phone via USB with USB Debugging enabled."
            }), 400

        _local_events.clear()

        # ── Run static app audit in background ──
        _engine_thread = threading.Thread(target=_engine.start, daemon=True)
        _engine_thread.start()

        return jsonify({
            "success": True,
            "session_id": _engine.pusher.session_id,
            "message": "Scan started. Events streaming to local dashboard."
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@scan_bp.route("/stop-scan", methods=["POST"])
def stop_scan():
    """Stop the current PhantomDroid scan session."""
    global _engine
    if _engine:
        _engine.stop()
        _engine = None
        return jsonify({"success": True, "message": "Scan stopped cleanly."})
    return jsonify({"success": False, "message": "No active scan found."}), 400


@scan_bp.route("/scan-status", methods=["GET"])
def scan_status():
    """Get current scan status."""
    if _engine and _engine.running:
        return jsonify({
            "active": True,
            "session_id": _engine.pusher.session_id,
            "device_id": _engine.device_id,
            "app_scores": _engine.analyzer.get_all_scores()
        })
    return jsonify({"active": False})


@scan_bp.route("/device-context", methods=["GET"])
def get_device_context():
    """Returns the cached context dict from ThreatAnalyzer.get_device_context()"""
    if _engine and _engine.analyzer.cached_context:
        return jsonify(_engine.analyzer.cached_context)
    # Return basic context even without scan
    try:
        from threat_analyzer import ThreatAnalyzer
        ta = ThreatAnalyzer()
        adb = get_adb_path()
        device_id = None
        result = subprocess.run([adb, "devices"], capture_output=True, text=True, timeout=10)
        lines = result.stdout.strip().split("\n")
        devices = [l for l in lines[1:] if "device" in l and "offline" not in l]
        if devices:
            device_id = devices[0].split("\t")[0]
        ctx = ta.get_device_context(adb, device_id)
        return jsonify(ctx)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@scan_bp.route("/device-check", methods=["GET"])
def device_check():
    """Check if an Android device is connected."""
    try:
        adb_path = get_adb_path()
        result = subprocess.run(
            [adb_path, "devices"], capture_output=True, text=True, timeout=15
        )
        lines = result.stdout.strip().split("\n")
        devices = [l for l in lines[1:] if "device" in l and "offline" not in l]
        return jsonify({
            "connected": len(devices) > 0,
            "device_count": len(devices),
            "devices": devices
        })
    except subprocess.TimeoutExpired:
        # Try resetting ADB
        try:
            adb_path = get_adb_path()
            subprocess.run([adb_path, "kill-server"], timeout=5)
            subprocess.run([adb_path, "start-server"], timeout=10)
            result = subprocess.run([adb_path, "devices"], capture_output=True, text=True, timeout=15)
            lines = result.stdout.strip().split("\n")
            devices = [l for l in lines[1:] if "device" in l and "offline" not in l]
            return jsonify({"connected": len(devices) > 0, "devices": devices})
        except Exception as e:
            return jsonify({"connected": False, "error": str(e)})
    except Exception as e:
        return jsonify({"connected": False, "error": str(e)})


@scan_bp.route("/live-events", methods=["GET"])
def get_live_events():
    """Endpoint for local dashboard to poll events if Firebase is missing."""
    since = request.args.get("since", 0, type=int)
    with _scan_lock:
        events = _local_events[since:]
    return jsonify({
        "events": events,
        "total": len(_local_events)
    })


@scan_bp.route("/narration", methods=["GET"])
def get_narration():
    """Return a real AI narration based on the most recent scan events."""
    is_final = request.args.get("is_final", "false").lower() == "true"
    try:
        from narrator import AINarrator
        with _scan_lock:
            recent = list(_local_events[-15:])  # Last 15 events for final summary
        
        if not recent:
            return jsonify({"text": "No events yet. Start a scan to receive live narration."})
        
        narrator = AINarrator()
        narration = narrator.narrate_events(recent, is_final=is_final)
        
        return jsonify({"text": narration, "event_count": len(recent)})
    except Exception as e:
        return jsonify({"text": f"AI Analyst monitoring — {len(_local_events)} events captured so far."})


# Global monitor instance
_monitor = None

@scan_bp.route("/start-monitor", methods=["POST"])
def start_monitor():
    """Start the background monitor daemon."""
    global _monitor
    data = request.json or {}
    mode = data.get("mode", "quick")
    target_app = data.get("target_app")

    if mode not in ("24hr", "quick", "live"):
        return jsonify({"success": False, "error": "Invalid mode. Must be '24hr', 'quick', or 'live'"}), 400

    from background_monitor import BackgroundMonitor
    
    # Clean up previous monitor if any
    if _monitor and _monitor.running:
        return jsonify({"success": False, "message": "Background monitor is already running."}), 400
        
    _monitor = BackgroundMonitor()

    # Wire monitor events into local dashboard feed
    original_push = _monitor.pusher.push_event
    def monitor_push(event):
        add_local_event(event)
        try:
            original_push(event)
        except Exception:
            pass
    _monitor.pusher.push_event = monitor_push

    success = _monitor.start(mode=mode, target_app=target_app)

    if success:
        return jsonify({
            "success": True,
            "session_id": _monitor.session_id,
            "message": f"Background monitor started in {mode} mode."
        })
    else:
        return jsonify({
            "success": False,
            "error": "Failed to start monitor. Check phone connection."
        }), 400

@scan_bp.route("/stop-monitor", methods=["POST"])
def stop_monitor():
    """Stop the background monitor daemon."""
    global _monitor
    if _monitor and _monitor.running:
        success = _monitor.stop()
        if success:
            return jsonify({"success": True, "message": "Background monitor stopped cleanly."})
    return jsonify({"success": False, "message": "No active background monitor found."}), 400


@scan_bp.route("/monitor-status", methods=["GET"])
def monitor_status():
    """Get the status of the background monitor daemon."""
    global _monitor
    if _monitor:
        status = _monitor.get_status()
        return jsonify(status)
    return jsonify({"running": False, "active": False})


@scan_bp.route("/ad-correlations", methods=["GET"])
def get_ad_correlations():
    """Get ad correlations for the current or specified session."""
    session_id = request.args.get("session_id")
    
    from sqlite_store import SQLiteStore
    store = SQLiteStore()
    
    if not session_id:
        # Fallback to current monitor session if running
        if _monitor and _monitor.session_id:
            session_id = _monitor.session_id
        else:
            # Fallback to the most recent session from the database
            try:
                conn = store.get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM sessions ORDER BY start_time DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    session_id = row["id"]
                cursor.close()
                conn.close()
            except Exception:
                pass
            
    if not session_id:
        return jsonify([])
        
    correlations = store.get_ad_correlations_by_session(session_id)
    return jsonify(correlations)
