
import sys
import os

print("--- Testing Imports ---")
try:
    import subprocess
    print("[+] subprocess imported")
    import threading
    print("[+] threading imported")
    import time
    print("[+] time imported")
    import re
    print("[+] re imported")
    
    # Manually import engine logic to find where it fails
    sys.path.insert(0, os.path.join(os.getcwd(), 'engine'))
    sys.path.insert(0, os.getcwd())
    print(f"Path added: {sys.path[0]}")
    
    print("Importing ThreatAnalyzer...")
    from engine.threat_analyzer import ThreatAnalyzer
    print("[+] ThreatAnalyzer imported")
    
    print("Importing FirebasePusher...")
    from engine.firebase_pusher import FirebasePusher
    print("[+] FirebasePusher imported")
    
    print("Importing ADBEngine...")
    from engine.adb_engine import ADBEngine
    print("[+] ADBEngine imported")
    
    print("Initializing ADBEngine...")
    engine = ADBEngine()
    print("[+] ADBEngine instance created")
    
    print("Checking device...")
    engine.check_device()
    print(f"Device ID: {engine.device_id}")
    
except Exception as e:
    print(f"\n[-] CRASH DETECTED: {e}")
    import traceback
    traceback.print_exc()
