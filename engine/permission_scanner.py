"""
PhantomDroid — Permission Scanner
Full deep scan of all installed apps and their permissions.
Runs once at the start of each session.
"""

import subprocess
import json
import os
from datetime import datetime
from adb_utils import get_adb_path

_ADB = get_adb_path()


PERMISSION_LABELS = {
    "RECORD_AUDIO": {"label": "Microphone", "icon": "🎤", "risk": "CRITICAL"},
    "CAMERA": {"label": "Camera", "icon": "📷", "risk": "CRITICAL"},
    "ACCESS_FINE_LOCATION": {"label": "GPS Location", "icon": "📍", "risk": "HIGH"},
    "ACCESS_BACKGROUND_LOCATION": {"label": "Background GPS", "icon": "🗺️", "risk": "CRITICAL"},
    "READ_SMS": {"label": "Read SMS", "icon": "💬", "risk": "HIGH"},
    "SEND_SMS": {"label": "Send SMS", "icon": "📤", "risk": "HIGH"},
    "READ_CONTACTS": {"label": "Read Contacts", "icon": "👥", "risk": "MEDIUM"},
    "WRITE_CONTACTS": {"label": "Edit Contacts", "icon": "✏️", "risk": "HIGH"},
    "READ_CALL_LOG": {"label": "Call History", "icon": "📞", "risk": "HIGH"},
    "PROCESS_OUTGOING_CALLS": {"label": "Intercept Calls", "icon": "☎️", "risk": "CRITICAL"},
    "READ_PHONE_STATE": {"label": "Phone Identity", "icon": "📱", "risk": "MEDIUM"},
    "BODY_SENSORS": {"label": "Body Sensors", "icon": "❤️", "risk": "MEDIUM"},
    "READ_EXTERNAL_STORAGE": {"label": "Read Files", "icon": "📁", "risk": "LOW"},
    "WRITE_EXTERNAL_STORAGE": {"label": "Write Files", "icon": "💾", "risk": "MEDIUM"},
}


class PermissionScanner:
    def __init__(self, device_id):
        self.device_id = device_id

    def run(self, db_conn=None):
        """
        Run full permission scan on all installed apps.
        Returns list of app permission profiles.
        """
        print("[+] Running full permission scan...")
        packages = self._get_packages()
        results = []

        for pkg in packages:
            profile = self._scan_app(pkg)
            if profile and profile["dangerous_count"] > 0:
                results.append(profile)
                print(f"  [{profile['risk_level']}] {pkg} — {profile['dangerous_count']} dangerous permissions")

        # Sort by risk score descending
        results.sort(key=lambda x: x["risk_score"], reverse=True)
        print(f"[+] Scan complete. {len(results)} apps with dangerous permissions found.")
        return results

    def _get_packages(self):
        """Get all third-party installed packages."""
        result = subprocess.run(
            [_ADB, "-s", self.device_id, "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True
        )
        return [l.replace("package:", "").strip() for l in result.stdout.strip().split("\n") if l]

    def _scan_app(self, package):
        """Scan a single app for dangerous permissions."""
        try:
            result = subprocess.run(
                [_ADB, "-s", self.device_id, "shell", "dumpsys", "package", package],
                capture_output=True, text=True, timeout=10
            )
            output = result.stdout
            granted_permissions = []

            for perm_key, perm_info in PERMISSION_LABELS.items():
                if perm_key in output and "granted=true" in output:
                    granted_permissions.append({
                        "permission": perm_key,
                        **perm_info
                    })

            if not granted_permissions:
                return None

            risk_score = sum(
                {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(p["risk"], 5)
                for p in granted_permissions
            )

            risk_level = (
                "CRITICAL" if risk_score >= 60 else
                "HIGH" if risk_score >= 30 else
                "MEDIUM" if risk_score >= 15 else "LOW"
            )

            return {
                "app": package,
                "permissions": granted_permissions,
                "dangerous_count": len(granted_permissions),
                "risk_score": min(100, risk_score),
                "risk_level": risk_level,
                "scanned_at": datetime.now().isoformat()
            }
        except Exception:
            return None

    def export_json(self, results, path="permission_scan.json"):
        """Export scan results to JSON file."""
        with open(path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {path}")
        return path
