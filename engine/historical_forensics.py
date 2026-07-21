"""
PhantomDroid — Historical Forensic Analyzer
Reads Android's cached system records to find past privacy violations.
Does NOT require apps to be open — reads what they DID in the past.

Data sources:
  - dumpsys appops  → who accessed mic/camera/GPS and WHEN
  - dumpsys netstats → data uploaded per app
  - dumpsys batterystats → background wakelock abuse
  - dumpsys usagestats → foreground/background time
"""

import subprocess
import re
import time
from datetime import datetime, timedelta
from collections import defaultdict


FINANCIAL_APPS = [
    "com.google.android.apps.nbu.paisa.user", "net.one97.paytm",
    "com.phonepe.app", "in.org.npci.upiapp", "com.amazon.mShop.android.shopping",
    "com.sbi.lotusintouch", "com.csam.icici.bank.imobile", "com.axis.mobile",
    "com.hdfcbank.HMobile", "com.kotak.mobile.android", "com.freecharge.android"
]

KNOWN_SAFE = [
    "com.google.android.dialer", "com.samsung.android.dialer",
    "com.android.camera", "com.samsung.camera", "com.google.android.apps.photos",
    "com.android.phone", "com.samsung.android.incallui"
]

# Permissions that are suspicious when accessed at night or in background
SENSITIVE_OPS = {
    "RECORD_AUDIO": ("RECORD_AUDIO", "🎤 Microphone"),
    "CAMERA": ("CAMERA", "📷 Camera"),
    "ACCESS_FINE_LOCATION": ("ACCESS_LOCATION", "📍 GPS"),
    "ACCESS_BACKGROUND_LOCATION": ("ACCESS_LOCATION", "🗺️ Background GPS"),
    "READ_CALL_LOG": ("READ_CALL_LOG", "📞 Call Log"),
    "READ_CONTACTS": ("READ_CONTACTS", "👥 Contacts"),
    "READ_SMS": ("READ_SMS", "💬 SMS"),
    "PROCESS_OUTGOING_CALLS": ("READ_CALL_LOG", "📞 Outgoing Calls"),
    "SEND_SMS": ("READ_SMS", "📤 Send SMS"),
}


class HistoricalForensicAnalyzer:
    def __init__(self, adb_path: str, device_id: str):
        self.adb_path = adb_path
        self.device_id = device_id

    def _run(self, cmd: str, timeout: int = 15) -> str:
        """Run adb shell command and return output."""
        try:
            result = subprocess.run(
                [self.adb_path, "-s", self.device_id, "shell"] + cmd.split(),
                capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except Exception as e:
            print(f"[-] ADB command failed: {cmd} → {e}")
            return ""

    def get_appops_history(self) -> list:
        """
        Read dumpsys appops — full history of which app accessed
        Mic, Camera, GPS, etc. and WHEN (even days ago).
        Returns list of events sorted by recency.
        """
        print("[+] Reading app permission history (dumpsys appops)...")
        output = self._run("dumpsys appops", timeout=30)
        events = []
        
        current_pkg = None
        current_op = None
        
        for line in output.split('\n'):
            # Package line: "Package com.instagram.android:"
            pkg_match = re.search(r'Package\s+([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,})', line)
            if pkg_match:
                current_pkg = pkg_match.group(1)
                continue

            # Op line: "RECORD_AUDIO: allow"
            op_match = re.search(r'^\s+(\w+): (\w+)', line)
            if op_match and current_pkg:
                op_name = op_match.group(1)
                if op_name in SENSITIVE_OPS:
                    current_op = op_name
                continue

            # Access time: "Access: [fg-svc]: Time=2024-03-11 23:15:42 Duration=1s"
            # or: "Last accessed: +1h5m37s330ms ago"
            time_match = re.search(r'Time=(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if time_match and current_pkg and current_op:
                access_time_str = time_match.group(1)
                try:
                    access_time = datetime.strptime(access_time_str, "%Y-%m-%d %H:%M:%S")
                    hours_ago = (datetime.now() - access_time).total_seconds() / 3600
                    is_night = 0 <= access_time.hour < 5
                    
                    # Determine if access mode was foreground or background
                    is_background = "bg" in line.lower() or "background" in line.lower()
                    is_foreground = "fg" in line.lower() or "foreground" in line.lower()

                    perm_key, perm_label = SENSITIVE_OPS[current_op]
                    
                    # Calculate suspicion score
                    score = 0
                    flags = []
                    
                    if is_night:
                        score += 30
                        flags.append("NIGHT")
                    if is_background:
                        score += 25
                        flags.append("BACKGROUND")
                    if current_pkg in FINANCIAL_APPS:
                        score += 20
                        flags.append("FINANCIAL")
                    if current_op in ("RECORD_AUDIO", "CAMERA") and is_background:
                        score += 20
                    if hours_ago < 1:
                        score += 10
                        flags.append("RECENT")
                    if current_pkg in KNOWN_SAFE:
                        score = 0  # Whitelist

                    if score > 0:
                        events.append({
                            "app": current_pkg,
                            "op": current_op,
                            "perm_label": perm_label,
                            "access_time": access_time.isoformat(),
                            "hours_ago": round(hours_ago, 1),
                            "is_night": is_night,
                            "is_background": is_background,
                            "perm_key": perm_key,
                            "flags": flags,
                            "score": min(100, score)
                        })
                except ValueError:
                    pass
                continue

            # Alternative: "ago" format "+5m ago"
            ago_match = re.search(r'\+(\d+)h(\d+)m.*ago', line)
            if ago_match and current_pkg and current_op:
                hours = int(ago_match.group(1))
                access_time = datetime.now() - timedelta(hours=hours)
                is_night = 0 <= access_time.hour < 5
                is_background = "bg" in line.lower()
                perm_key, perm_label = SENSITIVE_OPS[current_op]
                
                score = 0
                flags = []
                if is_night: score += 30; flags.append("NIGHT")
                if is_background: score += 25; flags.append("BACKGROUND")
                if current_op in ("RECORD_AUDIO", "CAMERA") and is_background: score += 20
                if hours < 1: flags.append("RECENT"); score += 10
                if current_pkg in KNOWN_SAFE: score = 0

                if score > 0:
                    events.append({
                        "app": current_pkg,
                        "op": current_op,
                        "perm_label": perm_label,
                        "access_time": access_time.isoformat(),
                        "hours_ago": round(hours + (datetime.now().minute / 60), 1),
                        "is_night": is_night,
                        "is_background": is_background,
                        "perm_key": perm_key,
                        "flags": flags,
                        "score": min(100, score)
                    })

        # Deduplicate and sort by score
        seen = set()
        unique = []
        for e in sorted(events, key=lambda x: -x["score"]):
            key = (e["app"], e["op"])
            if key not in seen:
                seen.add(key)
                unique.append(e)

        print(f"[+] Appops history: {len(unique)} suspicious access records found")
        return unique

    def get_network_usage(self) -> list:
        """
        Read network data usage per app.
        Identifies apps that upload unusually large amounts of data.
        """
        print("[+] Reading network data usage (dumpsys netstats)...")
        output = self._run("dumpsys netstats", timeout=20)
        app_data = defaultdict(lambda: {"tx": 0, "rx": 0})
        
        for line in output.split('\n'):
            # UID line: "UID=10187 ... tx=1234567 rx=9876543"
            uid_match = re.search(r'uid=(\d+).*txBytes=(\d+).*rxBytes=(\d+)', line, re.IGNORECASE)
            if not uid_match:
                uid_match = re.search(r'SET_DEFAULT.*uid=(\d+).*tx=(\d+).*rx=(\d+)', line)
            if uid_match:
                uid = uid_match.group(1)
                tx = int(uid_match.group(2))
                rx = int(uid_match.group(3))
                app_data[uid]["tx"] += tx
                app_data[uid]["rx"] += rx

        # Get UID→package mapping
        pkg_output = self._run("pm list packages -U")
        uid_to_pkg = {}
        for line in pkg_output.split('\n'):
            m = re.search(r'package:(.+) uid:(\d+)', line)
            if m:
                uid_to_pkg[m.group(2)] = m.group(1)

        events = []
        for uid, data in app_data.items():
            pkg = uid_to_pkg.get(uid)
            if not pkg or pkg.startswith("com.android.") or pkg.startswith("android"):
                continue
            
            tx_mb = data["tx"] / (1024 * 1024)
            rx_mb = data["rx"] / (1024 * 1024)
            
            # Flag apps uploading > 50MB
            if tx_mb > 50:
                score = min(100, int(tx_mb / 10))
                events.append({
                    "app": pkg,
                    "tx_mb": round(tx_mb, 1),
                    "rx_mb": round(rx_mb, 1),
                    "score": score,
                    "flag": "HIGH_UPLOAD" if tx_mb > 200 else "MODERATE_UPLOAD",
                    "description": f"{pkg} uploaded {tx_mb:.1f}MB of data"
                })

        return sorted(events, key=lambda x: -x["tx_mb"])

    def get_background_wakelock_abusers(self) -> list:
        """
        Check which apps keep the CPU awake while phone is supposed to be idle.
        Wakelock abuse = app preventing sleep = battery drain + covert activity.
        """
        print("[+] Reading battery/wakelock history (dumpsys batterystats)...")
        output = self._run("dumpsys batterystats --charged", timeout=30)
        abusers = []
        
        for line in output.split('\n'):
            # "Wakelock com.suspicious.app: 1h 45m 23s realtime"
            wl_match = re.search(r'Wakelock\s+([a-z][a-z0-9_]*(?:\.[a-z0-9_]+){1,}).*?(\d+)h\s*(\d+)m', line)
            if wl_match:
                pkg = wl_match.group(1)
                hours = int(wl_match.group(2))
                mins = int(wl_match.group(3))
                total_mins = hours * 60 + mins
                
                if pkg in KNOWN_SAFE or pkg.startswith("com.android."):
                    continue
                
                if total_mins > 30:  # More than 30 min of wakelock = suspicious
                    score = min(100, int(total_mins / 5))
                    abusers.append({
                        "app": pkg,
                        "wakelock_mins": total_mins,
                        "score": score,
                        "description": f"{pkg} kept CPU awake for {hours}h {mins}m (background activity)"
                    })

        return sorted(abusers, key=lambda x: -x["wakelock_mins"])

    def run_full_historical_scan(self, on_event=None) -> list:
        """
        Run all historical analyses and emit events in the standard format.
        """
        all_events = []

        # Phase 0a: What apps accessed sensitive permissions in the past?
        appops = self.get_appops_history()
        for record in appops:
            ago_str = f"{record['hours_ago']}h ago" if record['hours_ago'] > 1 else "recently"
            night_str = " at NIGHT (00:00-05:00)" if record['is_night'] else ""
            bg_str = " while running in BACKGROUND" if record['is_background'] else ""
            
            event = {
                "type": "historical_forensic",
                "app": record["app"],
                "permissions_involved": [record["perm_key"]],
                "threat_score": record["score"],
                "description": f"[HISTORY] {record['perm_label']} accessed {ago_str}{night_str}{bg_str}",
                "severity": "CRITICAL" if record["score"] >= 70 else "HIGH" if record["score"] >= 40 else "MEDIUM",
                "combo_triggered": "SLEEP_HOUR_CONTROL" if "NIGHT" in record["flags"] and "BACKGROUND" in record["flags"] else None,
                "is_false_positive": False,
                "is_odd_hour": record["is_night"],
                "timestamp": record["access_time"],
                "context": {
                    "screen_on": not record["is_background"],
                    "is_night": record["is_night"],
                    "call_active": False,
                    "financial_app_open": False,
                    "foreground_app": ""
                },
                "historical": True,
                "flags": record["flags"]
            }
            all_events.append(event)
            if on_event:
                on_event(event)

        # Phase 0b: Data upload anomalies
        net_events = self.get_network_usage()
        for record in net_events[:10]:  # Top 10 data hogs
            event = {
                "type": "network_forensic",
                "app": record["app"],
                "permissions_involved": ["NETWORK_UPLOAD"],
                "threat_score": record["score"],
                "description": f"[DATA] {record['app']} uploaded {record['tx_mb']}MB — potential data exfiltration",
                "severity": "HIGH" if record["tx_mb"] > 200 else "MEDIUM",
                "combo_triggered": "DATA_EXFILTRATION" if record["tx_mb"] > 200 else None,
                "is_false_positive": False,
                "is_odd_hour": False,
                "timestamp": datetime.now().isoformat(),
                "context": {"screen_on": True, "is_night": False, "call_active": False, "financial_app_open": False, "foreground_app": ""},
                "historical": True,
                "tx_mb": record["tx_mb"],
                "rx_mb": record["rx_mb"]
            }
            all_events.append(event)
            if on_event:
                on_event(event)

        # Phase 0c: Background wakelock abusers
        wl_events = self.get_background_wakelock_abusers()
        for record in wl_events[:5]:  # Top 5
            event = {
                "type": "wakelock_forensic",
                "app": record["app"],
                "permissions_involved": [],
                "threat_score": record["score"],
                "description": f"[SLEEP] {record['description']}",
                "severity": "HIGH" if record["wakelock_mins"] > 120 else "MEDIUM",
                "combo_triggered": None,
                "is_false_positive": False,
                "is_odd_hour": False,
                "timestamp": datetime.now().isoformat(),
                "context": {"screen_on": False, "is_night": False, "call_active": False, "financial_app_open": False, "foreground_app": ""},
                "historical": True,
                "wakelock_mins": record["wakelock_mins"]
            }
            all_events.append(event)
            if on_event:
                on_event(event)

        print(f"[+] Historical forensic scan complete: {len(all_events)} total records")
        return all_events
