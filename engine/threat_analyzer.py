"""
PhantomDroid — Threat Analyzer (Smart Context-Aware Version)
Parses raw ADB output, detects suspicious patterns,
and scores each app 0–100 based on behavior rules and context.
"""

import re
import time
import subprocess
from datetime import datetime
from collections import deque

FINANCIAL_APPS = [
    "com.google.android.apps.nbu.paisa.user",
    "net.one97.paytm",
    "com.phonepe.app",
    "in.org.npci.upiapp",
    "com.amazon.mShop.android.shopping",
    "com.sbi.lotusintouch",
    "com.csam.icici.bank.imobile",
    "com.axis.mobile",
    "com.hdfcbank.HMobile",
    "com.kotak.mobile.android",
    "com.freecharge.android"
]

WHITELIST_DIALERS = [
    "com.google.android.dialer",
    "com.samsung.android.dialer"
]

WHITELIST_CAMERAS = [
    "com.android.camera",
    "com.samsung.camera"
]

# Dangerous permission weights for initial scoring
PERMISSION_WEIGHTS = {
    "RECORD_AUDIO": 25,
    "CAMERA": 20,
    "ACCESS_FINE_LOCATION": 20,
    "ACCESS_BACKGROUND_LOCATION": 30,
    "READ_SMS": 25,
    "SEND_SMS": 20,
    "READ_CONTACTS": 10,
    "WRITE_CONTACTS": 15,
    "READ_CALL_LOG": 20,
    "PROCESS_OUTGOING_CALLS": 20,
    "READ_PHONE_STATE": 15,
    "BODY_SENSORS": 15,
    "READ_EXTERNAL_STORAGE": 10,
    "WRITE_EXTERNAL_STORAGE": 10,
}

class ThreatAnalyzer:
    def __init__(self):
        self.app_scores = {}
        self.cached_context = None
        self.context_cache_time = 0
        self.event_windows = {}

    def get_device_context(self, adb_path: str, device_id: str) -> dict:
        """
        Runs ADB shell commands to get device state and caches result for 10 seconds.
        """
        now = time.time()
        if self.cached_context and (now - self.context_cache_time < 10):
            return self.cached_context

        context = {
            "screen_on": True,
            "call_active": False,
            "screen_locked": False,
            "is_charging": False,
            "foreground_app": "",
            "is_night": False,
            "financial_app_open": False,
            "cached_at": datetime.now().isoformat()
        }

        if not adb_path or not device_id:
            return context

        try:
            # Helper to run adb command
            def run_adb(cmd):
                res = subprocess.run([adb_path, "-s", device_id, "shell"] + cmd.split(), capture_output=True, text=True, timeout=2)
                return res.stdout.strip()
            
            # 1. Screen State
            display_out = run_adb("dumpsys display")
            for line in display_out.split('\n'):
                if "mScreenState=" in line:
                    context["screen_on"] = "ON" in line
                    break

            # 2. Call State
            telephony_out = run_adb("dumpsys telephony.registry")
            for line in telephony_out.split('\n'):
                if "mCallState=" in line:
                    # 2 = OFFHOOK / Active call
                    state_val = line.split("mCallState=")[-1].strip()
                    context["call_active"] = state_val.startswith("2")
                    break

            # 3. Foreground App
            activity_out = run_adb("dumpsys activity activities")
            for line in activity_out.split('\n'):
                if "mCurrentFocus=" in line:
                    match = re.search(r'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})', line)
                    if match:
                        context["foreground_app"] = match.group(1)
                    break

            # 4. Screen Locked
            keyguard_out = run_adb("dumpsys keyguard")
            if "isKeyguardLocked=true" in keyguard_out:
                context["screen_locked"] = True

            # 5. Charging State
            battery_out = run_adb("dumpsys battery")
            if "powered: true" in battery_out.lower():
                context["is_charging"] = True

        except Exception as e:
            print(f"[-] ADB Context fetch error: {e}")

        # Night check
        hour = datetime.now().hour
        context["is_night"] = 0 <= hour < 5

        # Financial app check
        fg_app = context["foreground_app"]
        if fg_app in FINANCIAL_APPS:
            context["financial_app_open"] = True

        self.cached_context = context
        self.context_cache_time = now
        return context

    def analyze_log_line(self, line: str, adb_path: str = None, device_id: str = None) -> dict:
        """
        Analyze log line and apply 3-layer context-aware detection.
        """
        line = line.strip()
        if not line:
            return None

        app = self._extract_app(line)
        if not app:
            return None

        # ── DEEP PERMISSION DETECTION ──
        # These patterns fire when an app ACTIVELY uses a permission right now
        perms = []
        
        # Mic / Audio — catches AudioRecord, AudioFocus grabs, startRecording
        if re.search(r"RECORD_AUDIO|AudioRecord|startRecording|AudioFocus.GAIN|requestAudioFocus|MediaRecorder|openMicInput", line, re.IGNORECASE):
            perms.append("RECORD_AUDIO")
        
        # Camera — catches camera2 open, takePicture, camera preview start
        if re.search(r"CAMERA|openCamera|CameraDevice|takePicture|startPreview|camera\.open|ImageReader", line, re.IGNORECASE):
            perms.append("CAMERA")
        
        # Location — GPS fixes and background location
        if re.search(r"ACCESS_FINE_LOCATION|ACCESS_BACKGROUND_LOCATION|requestLocationUpdates|onLocationChanged|GpsLocationProvider|FusedLocation", line, re.IGNORECASE):
            perms.append("ACCESS_LOCATION")
        
        # Screen capture / overlay — payment intercept signal
        if re.search(r"READ_SCREEN|MediaProjection|captureScreen|createVirtualDisplay|SCREEN_CAPTURE", line, re.IGNORECASE):
            perms.append("READ_SCREEN")
        
        # High CPU/Network resource usage (data exfil signal)
        if re.search(r"uploadData|POST https|DataOutputStream|HttpURLConnection.*POST|sendto|ConnectivityManager.*upload", line, re.IGNORECASE):
            perms.append("NETWORK_UPLOAD")

        # Network connection to suspicious ad/analytics domains
        network_domain = None
        SUSPICIOUS_DOMAINS = [
            "doubleclick.net", "facebook.com", "adjust.com", "appsflyer.com",
            "mixpanel.com", "braze.com", "mparticle.com", "segment.com",
            "amplitude.com", "crashlytics.com", "bugsnag.com", "kochava.com"
        ]
        for domain in SUSPICIOUS_DOMAINS:
            if domain in line:
                network_domain = domain
                break

        if not perms and not network_domain:
            return None

        # Fetch context (cached for 10s — won't spam ADB)
        context = self.get_device_context(adb_path, device_id)
        
        # Track events in sliding window per app
        if app not in self.event_windows:
            self.event_windows[app] = deque(maxlen=20)
        
        now = time.time()
        # Clean old events older than 60s
        while self.event_windows[app] and now - self.event_windows[app][0]['time'] > 60:
            self.event_windows[app].popleft()

        self.event_windows[app].append({
            'time': now,
            'perms': perms,
            'network': network_domain
        })

        return self._detect_combo(app, perms, network_domain, context, line)


    def _detect_combo(self, app, perms, network_domain, context, line):
        combo_name = None
        score = 0
        severity = "LOW"
        is_false_positive = False
        justification = ""
        now = time.time()

        # Apply whitelist rules FIRST
        if "RECORD_AUDIO" in perms:
            if context["call_active"]:
                is_false_positive = True
                justification = "System detected an active call. Microphones are legally permitted for communication apps during calls."
            elif app in WHITELIST_DIALERS:
                is_false_positive = True
                justification = "This is a verified system dialer app. Mic access is expected for telephony."
            elif app == "com.whatsapp" and "pay" not in line.lower() and context["screen_on"]:
                is_false_positive = True
                justification = "Safe use: WhatsApp is using the mic while the screen is on (likely a voice note or call)."

        if "CAMERA" in perms:
            if context["screen_on"] and app == context["foreground_app"]:
                if app in WHITELIST_CAMERAS or app in ["com.instagram.android", "com.snapchat.android"]:
                    is_false_positive = True
                    justification = "Verified foreground use: You are currently using this camera app."

        if is_false_positive:
            score = 5
            severity = "INFORMATIONAL"
            description = f"{app} accessed {', '.join(perms)} (Authorized)"
        else:
            # 5 THREAT COMBOS
            # COMBO 1 — COVERT_RECORDING
            if ("RECORD_AUDIO" in perms or "CAMERA" in perms) and not context["screen_on"]:
                combo_name = "COVERT_RECORDING"
                score = 85
                severity = "CRITICAL"
                description = f"Covert Recording by {app}"
                justification = "CRITICAL: App accessed Mic/Camera while the screen was OFF. This is a primary indicator of spyware or background stalking."

            # COMBO 2 — PAYMENT_INTERCEPT
            elif ("RECORD_AUDIO" in perms or "CAMERA" in perms) and context["financial_app_open"]:
                if app not in FINANCIAL_APPS:
                    combo_name = "PAYMENT_INTERCEPT"
                    score = 95
                    severity = "CRITICAL"
                    description = f"Payment Data Intercept Risk: {app}"
                    justification = f"CRITICAL: {app} activated sensors while a financial/payment app was open. Risk of recording PINs or screen-scraping credit card data."

            # COMBO 3 — SLEEP_HOUR_CONTROL
            elif perms and context["is_night"] and not context["screen_on"]:
                combo_name = "SLEEP_HOUR_CONTROL"
                score = 80
                severity = "CRITICAL"
                description = f"Suspicious Activity at {datetime.now().strftime('%H:%M')}"
                justification = "WARNING: App accessed sensors during late-night hours while the phone was idle. High probability of background data harvesting."

            # COMBO 4 — DATA_EXFILTRATION
            elif network_domain:
                combo_name = "DATA_EXFILTRATION"
                score = 90
                severity = "CRITICAL"
                description = f"Potential Data Leak: {app}"
                justification = f"ALERT: {app} is uploading data to {network_domain} immediately after accessing sensors. This pattern suggests real-time data exfiltration."

            # COMBO 5 — MULTI_SENSOR_GRAB
            elif len(perms) >= 2:
                combo_name = "MULTI_SENSOR_GRAB"
                score = 75
                severity = "HIGH"
                description = f"Aggressive User Profiling: {app}"
                justification = "WARNING: App is grabbing multiple sensors (Mic + Location/Camera) at once. This is used to build a complete profile of your environment."

            # DEFAULT: Sensitive access in background
            elif app != context["foreground_app"] and context["screen_on"]:
                score = 40
                severity = "MEDIUM"
                description = f"Background Sensor Use"
                justification = f"NOTICE: {app} is using {', '.join(perms)} while you are using {context['foreground_app']}. Background access should be strictly reviewed."
            
            else:
                score = 20
                severity = "LOW"
                description = f"Standard App Activity"
                justification = f"SAFE USE: {app} is using permissions while active in the foreground. This appears to be normal user-triggered behavior."

        return {
            "app": app,
            "severity": severity,
            "threat_score": score,
            "description": description,
            "justification": justification,
            "combo_triggered": combo_name,
            "context": context,
            "permissions_involved": perms,
            "is_false_positive": is_false_positive,
            "timestamp": datetime.now().isoformat(),
            "is_odd_hour": context["is_night"]
        }


    def _extract_app(self, line):
        """Extract package name from logcat line."""
        match = re.search(r'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,})', line)
        if match:
            pkg = match.group(1)
            if not pkg.startswith(("android.", "com.android.", "dalvik.", "java.")):
                return pkg
        return None

    def score_permissions(self, permissions):
        """
        Calculate threat score from a list of granted permissions.
        Returns 0–100 score.
        """
        score = 0
        for perm in permissions:
            for weighted_perm, weight in PERMISSION_WEIGHTS.items():
                if weighted_perm in perm:
                    score += weight
                    break
        return min(100, score)

    def get_all_scores(self):
        """Return all current app scores as a dict."""
        return dict(self.app_scores)

    def parse_network_connections(self, proc_net_tcp_output: str) -> list:
        """
        Parses the output of 'cat /proc/net/tcp' from Android device.
        Returns a list of parsed connection dicts.
        """
        import socket
        
        def hex_to_ip_port(hex_str):
            try:
                ip_hex, port_hex = hex_str.split(':')
                # IP is little endian hex in proc/net/tcp
                ip_bytes = bytes.fromhex(ip_hex)
                ip = socket.inet_ntoa(ip_bytes[::-1]) # reverse for little-endian
                port = int(port_hex, 16)
                return ip, port
            except Exception:
                return None, None

        connections = []
        if not proc_net_tcp_output:
            return connections
            
        lines = proc_net_tcp_output.strip().split('\n')
        if len(lines) <= 1:
            return connections

        for line in lines[1:]: # Skip header
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            
            state = parts[3]
            if state != "01": # Only TCP_ESTABLISHED connections
                continue

            local_ip, local_port = hex_to_ip_port(parts[1])
            remote_ip, remote_port = hex_to_ip_port(parts[2])
            uid = parts[7]

            if remote_ip and remote_ip != "0.0.0.0" and remote_ip != "127.0.0.1":
                connections.append({
                    "type": "network_connection",
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "uid": uid,
                    "timestamp": datetime.now().isoformat()
                })
        return connections
