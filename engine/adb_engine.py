"""
PhantomDroid — ADB Engine
Connects to Android phone via ADB, reads live logcat,
extracts app activity, network calls, and permission grabs.
"""

import subprocess
import threading
import time
import re
import os
from datetime import datetime
from threat_analyzer import ThreatAnalyzer
from firebase_pusher import FirebasePusher

class ADBEngine:
    def __init__(self):
        self.analyzer = ThreatAnalyzer()
        self.pusher = FirebasePusher()
        self.running = False
        self.device_id = None
        self.on_event = None # Callback for local reporting
        self.logcat_process = None
        self.scanned_apps = set() # Cache to avoid redundant audits
        self._adb_path = self._get_adb_path()

    def _get_adb_path(self):
        """Get absolute path to adb executable.
        Priority: ADB_PATH env var > ANDROID_HOME/platform-tools > GlideX fallback > 'adb'
        """
        # 1. Explicit ADB_PATH in .env (most reliable)
        explicit = os.environ.get("ADB_PATH", "").strip()
        if explicit and os.path.exists(explicit):
            return explicit
        # 2. ANDROID_HOME/platform-tools (standard Android Studio install)
        android_home = os.environ.get("ANDROID_HOME", "").strip()
        if android_home:
            path = os.path.join(android_home, "platform-tools", "adb.exe")
            if os.path.exists(path):
                return path
        # 3. Known GlideX location on this machine
        glide_path = r"C:\Program Files\ASUS\GlideX\adb.exe"
        if os.path.exists(glide_path):
            return glide_path
        # 4. Fallback: assume adb is in system PATH
        return "adb"

    def _reset_adb(self):
        """Force reset the ADB server if it hangs."""
        print("[!] ADB timeout detected. Attempting server reset...")
        try:
            subprocess.run([self._adb_path, "kill-server"], timeout=10)
            time.sleep(2)
            subprocess.run([self._adb_path, "start-server"], timeout=10)
            time.sleep(1)
        except:
            pass

    def check_device(self, retry=True):
        """Check if Android device is connected via ADB."""
        try:
            result = subprocess.run(
                [self._adb_path, "devices"],
                capture_output=True, text=True, timeout=15
            )
            lines = result.stdout.strip().split("\n")
            devices = [l for l in lines[1:] if "device" in l and "offline" not in l]
            if devices:
                self.device_id = devices[0].split("\t")[0]
                print(f"[+] Device connected: {self.device_id}")
                return True
            else:
                print("[-] No Android device found. Connect phone via USB and enable USB Debugging.")
                return False
        except subprocess.TimeoutExpired:
            if retry:
                self._reset_adb()
                return self.check_device(retry=False)
            print("[-] ADB command timed out after reset.")
            return False
        except FileNotFoundError:
            print("[-] ADB not found. Install Android SDK Platform Tools.")
            return False

    def get_installed_apps(self):
        """Get list of all installed apps on device."""
        result = subprocess.run(
            [self._adb_path, "-s", self.device_id, "shell", "pm", "list", "packages", "-3"],
            capture_output=True, text=True
        )
        packages = [l.replace("package:", "").strip() for l in result.stdout.strip().split("\n") if l]
        print(f"[+] Found {len(packages)} third-party apps")
        return packages

    def get_app_permissions(self, package_name):
        """Get granted permissions for a package."""
        result = subprocess.run(
            [self._adb_path, "-s", self.device_id, "shell", "dumpsys", "package", package_name],
            capture_output=True, text=True
        )
        # Support various formats: 'permission.NAME: granted=true' or 'NAME: granted=true'
        matches = re.findall(r'(?:android\.permission\.)?([A-Z_0-9]+): granted=true', result.stdout)
        return list(set(matches))

    def stream_logcat(self):
        """Stream live logcat and detect suspicious activity."""
        print("[+] Starting live logcat stream...")
        self.logcat_process = subprocess.Popen(
            [self._adb_path, "-s", self.device_id, "logcat", "-v", "time", "-s",
             "ActivityManager", "PackageManager", "NetworkSecurityConfig",
             "WebViewFactory", "chromium", "NetworkStats", "PermissionManager",
             "audio", "camera", "location"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        while self.running and self.logcat_process:
            line = self.logcat_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            # KEY FIX: pass adb_path and device_id so context is fetched
            threat = self.analyzer.analyze_log_line(line, self._adb_path, self.device_id)
            if threat:
                self.pusher.push_event(threat)
                if self.on_event:
                    self.on_event(threat)
                print(f"[!] THREAT: {threat['app']} — {threat['description']}")

        if self.logcat_process:
            self.logcat_process.terminate()

    def scan_network_activity(self):
        """Scan current network connections from all apps."""
        while self.running:
            try:
                result = subprocess.run(
                    [self._adb_path, "-s", self.device_id, "shell", "cat", "/proc/net/tcp"],
                    capture_output=True, text=True, timeout=15
                )
                connections = self.analyzer.parse_network_connections(result.stdout)
                if connections:
                    for conn in connections:
                        self.pusher.push_event(conn)
                        if self.on_event:
                            self.on_event(conn)
            except Exception as e:
                print(f"[-] Network scan error: {e}")
            time.sleep(5)

    def get_active_audio_apps(self):
        """
        Ask the system who is currently using the mic/audio.
        This is the DEEP scan — catches apps like YT/Instagram using mic.
        Returns list of (package, is_recording) tuples.
        """
        try:
            result = subprocess.run(
                [self._adb_path, "-s", self.device_id, "shell", "dumpsys", "audio"],
                capture_output=True, text=True, timeout=10
            )
            active = []
            lines = result.stdout.split('\n')
            current_app = None
            for line in lines:
                pkg_match = re.search(r'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})', line)
                if pkg_match:
                    current_app = pkg_match.group(1)
                # AudioRecord in ACTIVE state
                if ("AudioRecord" in line or "RECORD" in line) and "ACTIVE" in line and current_app:
                    active.append((current_app, "MIC"))
                if ("AudioTrack" in line or "playback" in line.lower()) and "ACTIVE" in line and current_app:
                    active.append((current_app, "SPEAKER"))
            return active
        except Exception as e:
            print(f"[-] dumpsys audio error: {e}")
            return []

    def deep_activity_monitor(self, duration_seconds=120):
        """
        Run deep polling for active mic/camera/resource usage.
        Polls every 5 seconds. Stops automatically after duration.
        This catches apps like Instagram using mic during Reels.
        """
        print(f"[+] Deep activity monitor starting ({duration_seconds}s window)...")
        end_time = time.time() + duration_seconds
        
        while self.running and time.time() < end_time:
            # 1. Deep mic check via dumpsys audio
            active_audio = self.get_active_audio_apps()
            context = self.analyzer.get_device_context(self._adb_path, self.device_id)
            
            for pkg, sensor in active_audio:
                if pkg.startswith(("android.", "com.android.", "com.samsung.")):
                    continue  # Skip system apps
                
                event = self.analyzer._detect_combo(
                    pkg,
                    ["RECORD_AUDIO"] if sensor == "MIC" else [],
                    None,
                    context,
                    f"dumpsys audio: {pkg} ACTIVE {sensor}"
                )
                if event and not event.get("is_false_positive"):
                    event["description"] = f"⚡ {pkg} is ACTIVELY using {sensor} right now"
                    event["type"] = "deep_activity_scan"
                    self.pusher.push_event(event)
                    if self.on_event:
                        self.on_event(event)
                    print(f"[!] ACTIVE: {pkg} using {sensor}")
            
            time.sleep(5)
        
        print("[+] Deep activity monitor finished.")

    def start(self):
        """Start full PhantomDroid scan session with auto-stop."""
        if not self.check_device():
            return False

        print("\n👻 PHANTOMDROID SCAN STARTED")
        print("=" * 50)

        # Push session start
        self.pusher.start_session(self.device_id)
        self.running = True

        # ── PHASE 0: Historical Forensic Analysis ──
        # Reads Android's system records — no apps need to be open
        print("[+] Phase 0: Historical forensic analysis (appops, netstats, wakelocks)...")
        try:
            from historical_forensics import HistoricalForensicAnalyzer
            hfa = HistoricalForensicAnalyzer(self._adb_path, self.device_id)
            hfa.run_full_historical_scan(on_event=self.pusher.push_event)
            print("[+] Phase 0 complete.")
        except Exception as e:
            print(f"[-] Historical forensic scan error: {e}")

        # ── PHASE 1: Static permission audit (all apps) ──
        print("[+] Phase 1: Scanning installed apps...")
        apps = self.get_installed_apps()
        new_apps = [a for a in apps if a not in self.scanned_apps]
        total = len(new_apps)
        
        for i, app in enumerate(new_apps):
            if not self.running:
                break
            perms = self.get_app_permissions(app)
            if perms:
                self.scanned_apps.add(app)
                score = self.analyzer.score_permissions(perms)
                severity = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 20 else "LOW"
                event = {
                    "type": "permission_scan",
                    "app": app,
                    "permissions_involved": perms,
                    "permissions": perms,
                    "threat_score": score,
                    "description": f"{app} has {len(perms)} sensitive permissions",
                    "timestamp": datetime.now().isoformat(),
                    "severity": severity,
                    "combo_triggered": None,
                    "is_false_positive": False,
                    "is_odd_hour": False,
                    "scan_progress": f"{i+1}/{total}",
                    "context": {
                        "screen_on": True, "call_active": False,
                        "financial_app_open": False, "is_night": False, "foreground_app": ""
                    }
                }
                self.pusher.push_event(event)
                if self.on_event:
                    self.on_event(event)
        
        print(f"[+] Phase 1 complete: {total} apps scanned.")

        # ── PHASE 2: Live logcat + deep activity monitoring (2 min window) ──
        print("[+] Phase 2: Deep live activity monitoring (120s)...")
        logcat_thread = threading.Thread(target=self.stream_logcat, daemon=True)
        deep_thread = threading.Thread(target=self.deep_activity_monitor, args=(120,), daemon=True)
        logcat_thread.start()
        deep_thread.start()
        
        # Wait for deep monitor to finish, then auto-stop
        deep_thread.join()
        self.stop()
        
        # Signal frontend that scan is complete
        completion_event = {
            "type": "scan_complete",
            "app": "PhantomDroid",
            "description": f"Scan complete. {total} apps audited. Live monitoring finished.",
            "severity": "INFORMATIONAL",
            "threat_score": 0,
            "timestamp": datetime.now().isoformat(),
            "combo_triggered": None,
            "is_false_positive": True,
            "context": {},
            "permissions_involved": []
        }
        self.pusher.push_event(completion_event)
        if self.on_event:
            self.on_event(completion_event)
        
        return True

    def stop(self):
        """Stop the scan session cleanly (Windows + Mac/Linux compatible)."""
        print("[*] Stopping PhantomDroid scanner...")
        self.running = False
        
        # Kill logcat process properly on Windows
        if self.logcat_process:
            try:
                # Windows needs taskkill to properly kill ADB subprocess tree
                import subprocess, os, signal
                if os.name == 'nt':  # Windows
                    subprocess.run(
                        ['taskkill', '/F', '/T', '/PID', 
                         str(self.logcat_process.pid)],
                        capture_output=True
                    )
                else:  # Mac/Linux
                    self.logcat_process.terminate()
                    self.logcat_process.wait(timeout=3)
            except Exception as e:
                print(f"[-] Force kill error: {e}")
            finally:
                self.logcat_process = None
        
        # Also kill any lingering adb logcat processes on Windows
        if os.name == 'nt':
            try:
                subprocess.run(
                    ['taskkill', '/F', '/IM', 'adb.exe'],
                    capture_output=True
                )
            except:
                pass
        
        self.pusher.end_session()
        print("[+] Scan stopped." )


if __name__ == "__main__":
    engine = ADBEngine()
    try:
        if engine.start():
            input("\nPress ENTER to stop scan...\n")
    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
