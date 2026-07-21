import subprocess
import time
import os

adb_path = r"C:\Users\Nikhil\AppData\Local\Android\Sdk\platform-tools\adb.exe"

def check_device():
    print(f"[*] Checking ADB path: {adb_path}")
    if not os.path.exists(adb_path):
        print("[-] Path does not exist!")
        return
    
    try:
        print("[*] Running 'adb devices' with 15s timeout...")
        result = subprocess.run(
            [adb_path, "devices"],
            capture_output=True, text=True, timeout=15
        )
        print("[+] ADB Output:")
        print(result.stdout)
    except subprocess.TimeoutExpired:
        print("[!] TIMEOUT detected. Attempting kill-server...")
        subprocess.run([adb_path, "kill-server"])
        time.sleep(2)
        subprocess.run([adb_path, "start-server"])
        print("[*] Retrying 'adb devices'...")
        result = subprocess.run([adb_path, "devices"], capture_output=True, text=True, timeout=15)
        print(result.stdout)
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    check_device()
