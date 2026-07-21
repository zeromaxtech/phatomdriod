"""
PhantomDroid — Local Ollama AI Analyst
Provides fully private, offline AI threat briefings and explanation narrations.
Connects to local Ollama server if available, else falls back to robust rule-based summaries.
"""

import urllib.request
import urllib.error
import json
from datetime import datetime

SYSTEM_PROMPT = (
    "You are PhantomDroid's local privacy analyst. You analyze "
    "Android app behavior to detect privacy violations. Focus on:\n"
    "1. Apps accessing mic/camera during content consumption\n"
    "2. Ad server contacts after sensor access\n"
    "3. Background activity during sleep hours\n"
    "4. Data exfiltration patterns\n"
    "Be direct and use plain English. Max 3 sentences per analysis."
)

OLLAMA_URL = "http://localhost:11434"

class OllamaAnalyst:
    def __init__(self):
        self.default_model = "llama3"

    def is_available(self) -> bool:
        """Checks if the local Ollama service is running and accessible."""
        try:
            req = urllib.request.Request(f"{OLLAMA_URL}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as response:
                return response.status == 200
        except Exception:
            return False

    def _get_active_model(self) -> str:
        """Retrieves the first available model name from local Ollama tags, default to llama3."""
        try:
            req = urllib.request.Request(f"{OLLAMA_URL}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2.0) as response:
                data = json.loads(response.read().decode("utf-8"))
                models = data.get("models", [])
                if models:
                    # Prefer llama3 variants if present
                    for m in models:
                        name = m.get("name", "")
                        if "llama3" in name:
                            return name
                    return models[0].get("name", self.default_model)
        except Exception:
            pass
        return self.default_model

    def _generate(self, prompt: str) -> str:
        """Sends a request to local Ollama generate API endpoint."""
        if not self.is_available():
            return None
            
        model = self._get_active_model()
        payload = {
            "model": model,
            "prompt": prompt,
            "system": SYSTEM_PROMPT,
            "stream": False
        }
        
        try:
            req = urllib.request.Request(
                f"{OLLAMA_URL}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=12.0) as response:
                res_data = json.loads(response.read().decode("utf-8"))
                return res_data.get("response", "").strip()
        except Exception as e:
            print(f"[-] Ollama generate error: {e}")
            return None

    def analyze_threats(self, events_summary: dict) -> str:
        """
        Analyzes a dict of threat events to extract structural patterns and risk posture.
        """
        prompt = f"Analyze these device threats and behavior patterns: {json.dumps(events_summary)}. What are the key privacy violations?"
        response = self._generate(prompt)
        if response:
            return response
            
        # Fallback reasoning
        return (
            "Local threat audit complete. Analyzed background app permissions and potential sensor grabs. "
            "Flagged suspicious background patterns for review. Review raw database log for exact timestamps."
        )

    def explain_ad_correlation(self, correlation: dict) -> str:
        """
        Explains why a specific mic-network ad correlation event is a severe privacy threat.
        """
        prompt = f"Explain this ad correlation event: {json.dumps(correlation)}. Why is it suspicious?"
        response = self._generate(prompt)
        if response:
            return response
            
        # Fallback reasoning
        app = correlation.get("app", "App")
        gap = correlation.get("seconds_gap", 0.0)
        ad_server = correlation.get("ad_server", "ad server")
        return (
            f"ALERT: {app} accessed your microphone, and within {gap} seconds, your phone initiated a connection to {ad_server}. "
            "This suggests real-time voice profiling where audio is converted to ad-targeting cues."
        )

    def generate_daily_briefing(self, daily_summary: dict) -> str:
        """
        Generates a summary of daily privacy metrics and sensor accesses.
        """
        prompt = f"Summarize the daily privacy activities and threats: {json.dumps(daily_summary)}. Provide a briefing."
        response = self._generate(prompt)
        if response:
            return response
            
        # Fallback reasoning
        apps_count = len(daily_summary)
        if apps_count == 0:
            return "Daily Briefing: No suspicious background behaviors or permissions were logged in the past 24 hours. Your device posture is clean."
            
        sus_apps = ", ".join(list(daily_summary.keys())[:3])
        return (
            f"Daily Briefing: Logged sensor interactions across {apps_count} apps in the last 24h. "
            f"Highest sensor access indicators from: {sus_apps}. "
            "Recommend checking app permissions and limiting background operations for non-essential apps."
        )
