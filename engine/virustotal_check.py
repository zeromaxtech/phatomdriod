"""
PhantomDroid — VirusTotal Checker
Hashes APK files found on device,
checks against VirusTotal API for known malware.
"""

import subprocess
import hashlib
import requests
import os
import time
import tempfile
from dotenv import load_dotenv
from adb_utils import get_adb_path

load_dotenv()

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
_ADB = get_adb_path()


class VirusTotalChecker:
    def __init__(self, device_id):
        self.device_id = device_id
        self.headers = {"x-apikey": VT_API_KEY}

    def find_apks(self):
        """Find APK files on device storage."""
        result = subprocess.run(
            [_ADB, "-s", self.device_id, "shell",
             "find", "/sdcard", "-name", "*.apk", "-type", "f"],
            capture_output=True, text=True, timeout=15
        )
        apks = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
        print(f"[+] Found {len(apks)} APK files on device")
        return apks

    def pull_and_hash(self, device_path):
        """Pull APK from device and compute SHA256 hash."""
        local_path = os.path.join(tempfile.gettempdir(), os.path.basename(device_path))
        subprocess.run(
            [_ADB, "-s", self.device_id, "pull", device_path, local_path],
            capture_output=True
        )
        if not os.path.exists(local_path):
            return None, None

        sha256 = hashlib.sha256()
        with open(local_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)

        os.remove(local_path)
        return sha256.hexdigest(), os.path.basename(device_path)

    def check_hash(self, file_hash):
        """Check a file hash against VirusTotal database."""
        if not VT_API_KEY:
            print("[-] No VirusTotal API key found in .env")
            return None

        try:
            response = requests.get(
                f"{VT_BASE_URL}/files/{file_hash}",
                headers=self.headers,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                return {
                    "hash": file_hash,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "clean": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "is_malware": stats.get("malicious", 0) > 3
                }
            elif response.status_code == 404:
                return {"hash": file_hash, "malicious": 0, "status": "not_found"}
        except requests.RequestException as e:
            print(f"[-] VirusTotal API error: {e}")
        return None

    def scan_all(self):
        """
        Find, hash, and scan all APKs on device.
        Returns list of scan results.
        """
        apks = self.find_apks()
        results = []

        for apk_path in apks[:10]:  # Limit to 10 to respect API rate limits
            print(f"  Checking: {os.path.basename(apk_path)}")
            file_hash, filename = self.pull_and_hash(apk_path)
            if not file_hash:
                continue

            vt_result = self.check_hash(file_hash)
            if vt_result:
                vt_result["filename"] = filename
                vt_result["device_path"] = apk_path
                results.append(vt_result)

                if vt_result.get("is_malware"):
                    print(f"  [!!!] MALWARE DETECTED: {filename}")
                    print(f"        Flagged by {vt_result['malicious']} engines!")

            time.sleep(1)  # VirusTotal free tier: 4 requests/min

        return results
