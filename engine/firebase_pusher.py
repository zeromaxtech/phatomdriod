"""
PhantomDroid — Firebase Pusher
Streams threat events to Firebase Realtime Database
in real-time using pyrebase4.
"""

try:
    import pyrebase
except ImportError:
    print("[-] Error: 'pyrebase' module not found.")
    print("[!] Please run: python -m pip install pyrebase4")
    # We don't exit here so the rest of the engine can still try to load in 'dry run' mode if needed,
    # but most likely it will fail later.
    pyrebase = None
import os
import uuid
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Firebase config — loaded from environment variables
FIREBASE_CONFIG = {
    "apiKey": os.getenv("FIREBASE_API_KEY"),
    "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
    "databaseURL": os.getenv("FIREBASE_DATABASE_URL"),
    "projectId": os.getenv("FIREBASE_PROJECT_ID"),
    "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
    "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
    "appId": os.getenv("FIREBASE_APP_ID")
}


class FirebasePusher:
    def __init__(self):
        self.db = None
        self.session_id = None
        self.dry_run = False
        
        try:
            # Check if config is just placeholders
            is_placeholder = FIREBASE_CONFIG.get("databaseURL") and "your-project" in FIREBASE_CONFIG.get("databaseURL")
            
            if not FIREBASE_CONFIG.get("apiKey") or is_placeholder:
                print("[!] Firebase not configured or using placeholders. Entering DRY RUN mode.")
                print("[!] Threats will be printed to console but won't show on web dashboard.")
                self.dry_run = True
                return

            firebase = pyrebase.initialize_app(FIREBASE_CONFIG)
            self.db = firebase.database()
            print("[+] Firebase connected")
        except Exception as e:
            print(f"[-] Firebase connection failed: {e}")
            print("[!] Entering DRY RUN mode.")
            self.dry_run = True

    def start_session(self, device_id):
        """Create a new scan session in Firebase."""
        self.session_id = str(uuid.uuid4())[:8]
        if self.dry_run:
            print(f"[DRY RUN] Session started: {self.session_id} for device {device_id}")
            return self.session_id

        session_data = {
            "session_id": self.session_id,
            "device_id": device_id,
            "start_time": datetime.now().isoformat(),
            "status": "active",
            "threat_count": 0
        }
        if self.db:
            try:
                self.db.child("sessions").child(self.session_id).set(session_data)
                print(f"[+] Session started: {self.session_id}")
            except Exception as e:
                print(f"[-] Failed to start Firebase session: {e}. Switching to DRY RUN.")
                self.dry_run = True
        return self.session_id

    def push_event(self, event):
        """Push a single threat event to Firebase."""
        if not self.db or not self.session_id:
            print(f"[DRY RUN] Event: {event.get('description', 'unknown')}")
            return

        try:
            # Add session context
            event["session_id"] = self.session_id

            # Push to events feed (for live dashboard)
            self.db.child("events").child(self.session_id).push(event)

            # Update app threat score
            app = event.get("app", "unknown")
            score = event.get("threat_score", 0)
            self.db.child("app_scores").child(self.session_id).child(
                app.replace(".", "_")
            ).set({
                "app": app,
                "score": score,
                "last_seen": datetime.now().isoformat(),
                "severity": event.get("severity", "LOW")
            })

            # Increment session threat count
            try:
                current = self.db.child("sessions").child(self.session_id).get().val()
                count = (current.get("threat_count", 0) if current else 0) + 1
                self.db.child("sessions").child(self.session_id).update({
                    "threat_count": count
                })
            except:
                pass

        except Exception as e:
            print(f"[-] Firebase push failed: {e}")

    def push_ai_narration(self, narration):
        """Push Claude AI narration to Firebase."""
        if self.db and self.session_id:
            self.db.child("narration").child(self.session_id).push({
                "text": narration,
                "timestamp": datetime.now().isoformat()
            })

    def end_session(self):
        """Mark session as complete in Firebase."""
        if self.db and self.session_id:
            self.db.child("sessions").child(self.session_id).update({
                "status": "complete",
                "end_time": datetime.now().isoformat()
            })
            print(f"[+] Session {self.session_id} saved to Firebase")
