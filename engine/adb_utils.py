"""
PhantomDroid — ADB Path Utility
Shared resolver for adb.exe location.
Import this in any module that needs to invoke ADB.

Priority order:
  1. ADB_PATH  env var  (set in .env explicitly)
  2. ANDROID_HOME/platform-tools/adb.exe  (standard Android Studio)
  3. C:\\Program Files\\ASUS\\GlideX\\adb.exe  (found on this machine)
  4. "adb"  (assumes it's in the system PATH)
"""

import os
from dotenv import load_dotenv

load_dotenv()

_CACHED_ADB_PATH = None


def get_adb_path() -> str:
    """Return the absolute path to adb.exe (cached after first call)."""
    global _CACHED_ADB_PATH
    if _CACHED_ADB_PATH:
        return _CACHED_ADB_PATH

    # 1. Explicit ADB_PATH in .env
    explicit = os.environ.get("ADB_PATH", "").strip()
    if explicit and os.path.exists(explicit):
        _CACHED_ADB_PATH = explicit
        return _CACHED_ADB_PATH

    # 2. ANDROID_HOME/platform-tools (standard SDK install)
    android_home = os.environ.get("ANDROID_HOME", "").strip()
    if android_home:
        candidate = os.path.join(android_home, "platform-tools", "adb.exe")
        if os.path.exists(candidate):
            _CACHED_ADB_PATH = candidate
            return _CACHED_ADB_PATH

    # 3. ASUS GlideX (found on this machine)
    glide_path = r"C:\Program Files\ASUS\GlideX\adb.exe"
    if os.path.exists(glide_path):
        _CACHED_ADB_PATH = glide_path
        return _CACHED_ADB_PATH

    # 4. System PATH fallback
    _CACHED_ADB_PATH = "adb"
    return _CACHED_ADB_PATH
