"""
PhantomDroid — Background Monitor Daemon
Runs three concurrent worker threads to capture Android logs, network logs, and device state.
Logs threat events to local SQLite database and pushes to Firebase in real-time.
"""

import threading
import time
import subprocess
import os
import re
import socket
from datetime import datetime
from sqlite_store import SQLiteStore
from ad_correlation import correlate
from ollama_analyst import OllamaAnalyst
from threat_analyzer import ThreatAnalyzer
from firebase_pusher import FirebasePusher

class BackgroundMonitor:
    def __init__(self):
        self.store = SQLiteStore()
        self.analyst = OllamaAnalyst()
        self.analyzer = ThreatAnalyzer()
        self.pusher = FirebasePusher()
        
        self.running = False
        self.session_id = None
        self.device_id = None
        self.mode = "live"
        self.target_app = None
        self.start_time = None
        self.end_time = None
        
        # Threads and processes
        self.logcat_process = None
        self.workers = []
        self._adb_path = self._get_adb_path()
        
        # Sliding windows for ad correlation (thread-safe lock)
        self.lock = threading.Lock()
        self.recent_mic_events = []
        self.recent_network_events = []
        
        # Stats counters
        self.event_count = 0
        self.threat_count = 0
        
        # Cached UID -> Package mapping
        self.uid_cache = {}

    def _get_adb_path(self):
        """Get absolute path to adb executable.
        Priority: ADB_PATH env var > ANDROID_HOME/platform-tools > GlideX fallback > 'adb'
        """
        explicit = os.environ.get("ADB_PATH", "").strip()
        if explicit and os.path.exists(explicit):
            return explicit
        android_home = os.environ.get("ANDROID_HOME", "").strip()
        if android_home:
            path = os.path.join(android_home, "platform-tools", "adb.exe")
            if os.path.exists(path):
                return path
        glide_path = r"C:\Program Files\ASUS\GlideX\adb.exe"
        if os.path.exists(glide_path):
            return glide_path
        return "adb"

    def _get_packages_uid_mapping(self):
        """Builds cached mapping of UID to package name to avoid repeated shell calls."""
        if self.uid_cache:
            return self.uid_cache
            
        try:
            result = subprocess.run(
                [self._adb_path, "-s", self.device_id, "shell", "pm", "list", "packages", "-U"],
                capture_output=True, text=True, timeout=10
            )
            mapping = {}
            for line in result.stdout.strip().split("\n"):
                match = re.search(r'package:(.+) uid:(\d+)', line)
                if match:
                    pkg = match.group(1).strip()
                    uid = match.group(2).strip()
                    mapping[uid] = pkg
            self.uid_cache = mapping
        except Exception as e:
            print(f"[-] Error listing packages for UID mapping: {e}")
        return self.uid_cache

    def check_device(self) -> bool:
        """Check if an Android device is connected via ADB."""
        try:
            result = subprocess.run(
                [self._adb_path, "devices"],
                capture_output=True, text=True, timeout=10
            )
            lines = result.stdout.strip().split("\n")
            devices = [l for l in lines[1:] if "device" in l and "offline" not in l]
            if devices:
                self.device_id = devices[0].split("\t")[0]
                return True
        except Exception:
            pass
        return False

    def start(self, mode="live", target_app=None):
        """Starts the background monitor session."""
        if self.running:
            print("[!] Monitor is already running.")
            return False

        if not self.check_device():
            print("[-] No device connected. Cannot start monitor.")
            return False

        self.running = True
        self.mode = mode
        self.target_app = target_app
        self.start_time = datetime.now()
        self.end_time = None
        self.event_count = 0
        self.threat_count = 0
        self.recent_mic_events.clear()
        self.recent_network_events.clear()
        
        # Clear UID cache to refresh package map
        self.uid_cache.clear()
        self._get_packages_uid_mapping()

        # Start session in database and firebase
        self.session_id = self.pusher.start_session(self.device_id)
        
        session_data = {
            "id": self.session_id,
            "session_id": self.session_id,
            "start_time": self.start_time.isoformat(),
            "mode": self.mode,
            "total_events": 0,
            "device_id": self.device_id,
            "status": "active"
        }
        self.store.save_session(session_data)
        
        print(f"[+] Monitor started. Session: {self.session_id}, Mode: {self.mode}")

        # Spawn workers
        t_logcat = threading.Thread(target=self.logcat_worker, daemon=True)
        t_network = threading.Thread(target=self.network_worker, daemon=True)
        t_context = threading.Thread(target=self.context_worker, daemon=True)
        
        self.workers = [t_logcat, t_network, t_context]
        for t in self.workers:
            t.start()

        # Auto-stop timer thread if not in "live" mode
        if self.mode == "quick":
            threading.Thread(target=self._auto_stop_timer, args=(180,), daemon=True).start()
        elif self.mode == "24hr":
            threading.Thread(target=self._auto_stop_timer, args=(86400,), daemon=True).start()

        return True

    def _auto_stop_timer(self, seconds):
        """Thread helper to automatically trigger monitor stop after interval."""
        time.sleep(seconds)
        if self.running:
            print(f"[+] Auto-stop timer expired ({seconds}s). Stopping monitor...")
            self.stop()

    def logcat_worker(self):
        """Worker thread checking live logcat lines."""
        print("[+] Logcat worker started.")
        # Clear logcat buffers first to avoid processing old lines
        try:
            subprocess.run([self._adb_path, "-s", self.device_id, "logcat", "-c"], timeout=5)
        except Exception:
            pass

        self.logcat_process = subprocess.Popen(
            [self._adb_path, "-s", self.device_id, "logcat", "-v", "time", "-s",
             "ActivityManager", "PackageManager", "NetworkSecurityConfig",
             "WebViewFactory", "chromium", "NetworkStats", "PermissionManager",
             "audio", "camera", "location"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )

        while self.running and self.logcat_process:
            line = self.logcat_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue

            threat = self.analyzer.analyze_log_line(line, self._adb_path, self.device_id)
            if threat:
                # Filter by target app if live-targeting is enabled
                if self.target_app and threat.get("app") != self.target_app:
                    continue

                # Add session info
                threat["session_id"] = self.session_id
                
                # Check if it contains mic/camera access
                perms = threat.get("permissions_involved", [])
                is_mic = "RECORD_AUDIO" in perms

                self.lock.acquire()
                try:
                    self.event_count += 1
                    if threat.get("severity") in ("HIGH", "CRITICAL"):
                        self.threat_count += 1
                        
                    # Save event to store
                    self.store.save_event(threat)
                    
                    # Stream event to Firebase
                    self.pusher.push_event(threat)

                    if is_mic:
                        self.recent_mic_events.append(threat)
                        # Limit memory space (keep last 50 mic events)
                        if len(self.recent_mic_events) > 50:
                            self.recent_mic_events.pop(0)
                        
                        # Immediately run ad correlation check
                        corr = correlate(threat, self.recent_network_events)
                        if corr:
                            corr["session_id"] = self.session_id
                            # Save correlation
                            self.store.save_ad_correlation(corr)
                            # Push correlation event info to Firebase
                            corr_event = {
                                "type": "ad_correlation",
                                "app": corr["app"],
                                "severity": "CRITICAL",
                                "threat_score": 90,
                                "description": f"⚡ Ad Profiling: {corr['app']} contacted {corr['ad_server']} shortly after mic access.",
                                "timestamp": corr["timestamp"],
                                "combo_triggered": "DATA_EXFILTRATION",
                                "context": threat.get("context", {}),
                                "permissions_involved": ["RECORD_AUDIO", "NETWORK_UPLOAD"],
                                "is_false_positive": False,
                                "ad_correlation_json": json.dumps(corr)
                            }
                            self.store.save_event(corr_event)
                            self.pusher.push_event(corr_event)
                finally:
                    self.lock.release()

        if self.logcat_process:
            try:
                self.logcat_process.terminate()
            except:
                pass
            self.logcat_process = None
        print("[-] Logcat worker stopped.")

    def network_worker(self):
        """Worker thread checking network connections from Android /proc/net/tcp."""
        print("[+] Network worker started.")
        while self.running:
            try:
                result = subprocess.run(
                    [self._adb_path, "-s", self.device_id, "shell", "cat", "/proc/net/tcp"],
                    capture_output=True, text=True, timeout=8
                )
                connections = self.analyzer.parse_network_connections(result.stdout)
                
                if connections:
                    uid_map = self._get_packages_uid_mapping()
                    now_str = datetime.now().isoformat()
                    
                    self.lock.acquire()
                    try:
                        for conn in connections:
                            uid = conn.get("uid")
                            pkg = uid_map.get(uid, "unknown")
                            
                            # Exclude system package logs to keep memory low
                            if pkg.startswith(("android.", "com.android.", "com.samsung.", "unknown")):
                                continue
                                
                            if self.target_app and pkg != self.target_app:
                                continue

                            # Try reverse DNS lookup for domains in background
                            remote_ip = conn.get("remote_ip")
                            remote_host = remote_ip
                            try:
                                # Quick lookup, low timeout
                                socket.setdefaulttimeout(0.5)
                                remote_host = socket.gethostbyaddr(remote_ip)[0]
                            except Exception:
                                pass

                            net_event = {
                                "type": "network_connection",
                                "app": pkg,
                                "remote_ip": remote_ip,
                                "network": remote_host,
                                "timestamp": now_str
                            }
                            
                            self.recent_network_events.append(net_event)
                            # Space optimization: keep last 100 network connections
                            if len(self.recent_network_events) > 100:
                                self.recent_network_events.pop(0)

                            # Immediately check correlation if a new network call occurs
                            # Matches recent mic accesses
                            for mic_ev in self.recent_mic_events:
                                if mic_ev.get("app") == pkg:
                                    corr = correlate(mic_ev, [net_event])
                                    if corr:
                                        corr["session_id"] = self.session_id
                                        self.store.save_ad_correlation(corr)
                                        
                                        corr_event = {
                                            "type": "ad_correlation",
                                            "app": corr["app"],
                                            "severity": "CRITICAL",
                                            "threat_score": 90,
                                            "description": f"⚡ Ad Profiling: {corr['app']} contacted {corr['ad_server']} shortly after mic access.",
                                            "timestamp": corr["timestamp"],
                                            "combo_triggered": "DATA_EXFILTRATION",
                                            "context": mic_ev.get("context", {}),
                                            "permissions_involved": ["RECORD_AUDIO", "NETWORK_UPLOAD"],
                                            "is_false_positive": False,
                                            "ad_correlation_json": json.dumps(corr)
                                        }
                                        self.store.save_event(corr_event)
                                        self.pusher.push_event(corr_event)
                    finally:
                        self.lock.release()
            except Exception as e:
                print(f"[-] Network worker error: {e}")
            
            # Query every 5 seconds
            time.sleep(5)
        print("[-] Network worker stopped.")

    def context_worker(self):
        """Worker thread updating device context cached properties every 10 seconds."""
        print("[+] Context worker started.")
        while self.running:
            try:
                # Triggers threat analyzer to run adb shell context updates
                self.analyzer.get_device_context(self._adb_path, self.device_id)
            except Exception as e:
                print(f"[-] Context worker error: {e}")
            time.sleep(10)
        print("[-] Context worker stopped.")

    def stop(self):
        """Terminates the background monitor and generates AI summaries."""
        if not self.running:
            return False

        print("[*] Stopping background monitor...")
        self.running = False
        self.end_time = datetime.now()

        # Windows Process Clean-up
        if self.logcat_process:
            try:
                if os.name == 'nt':  # Windows
                    subprocess.run(
                        ['taskkill', '/F', '/T', '/PID', str(self.logcat_process.pid)],
                        capture_output=True, timeout=5
                    )
                else:
                    self.logcat_process.terminate()
                    self.logcat_process.wait(timeout=3)
            except Exception as e:
                print(f"[-] Logcat terminate error: {e}")
            self.logcat_process = None

        # Clean lingering adb.exe processes on Windows to prevent resource locks
        if os.name == 'nt':
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'adb.exe'], capture_output=True, timeout=5)
            except:
                pass

        # Wait for threads to close
        for t in self.workers:
            try:
                t.join(timeout=2.0)
            except:
                pass
        self.workers.clear()

        # Generate local AI Briefing
        ai_briefing = None
        try:
            daily_summary = self.store.get_daily_summary()
            if self.analyst.is_available():
                ai_briefing = self.analyst.generate_daily_briefing(daily_summary)
            else:
                # Fallback to local rule-based analyst narration generator
                ai_briefing = self.analyst.generate_daily_briefing(daily_summary)
        except Exception as e:
            print(f"[-] Error generating AI briefing on stop: {e}")

        # Update session info
        session_data = {
            "id": self.session_id,
            "session_id": self.session_id,
            "end_time": self.end_time.isoformat(),
            "status": "complete",
            "total_events": self.event_count,
            "ai_briefing": ai_briefing
        }
        self.store.save_session(session_data)
        
        # Finalize in Firebase
        self.pusher.end_session()
        if ai_briefing:
            self.pusher.push_ai_narration(ai_briefing)

        print(f"[+] Monitor stopped. Briefing: {ai_briefing}")
        return True

    def get_status(self) -> dict:
        """Returns the monitor runtime statistics and state."""
        runtime = 0
        if self.running and self.start_time:
            runtime = int((datetime.now() - self.start_time).total_seconds())
        elif self.start_time and self.end_time:
            runtime = int((self.end_time - self.start_time).total_seconds())

        return {
            "running": self.running,
            "session_id": self.session_id,
            "device_id": self.device_id,
            "mode": self.mode,
            "target_app": self.target_app,
            "runtime_seconds": runtime,
            "event_count": self.event_count,
            "threat_count": self.threat_count
        }
