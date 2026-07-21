"""
PhantomDroid — AI Narrator
Sends threat events to the multi-API client and gets
plain-English security narration in real time.
Providers tried in order: Groq → Cerebras → OpenRouter (Qwen) → Gemini.
"""

import json
import os
from datetime import datetime
from dotenv import load_dotenv
from prompts import (
    NARRATOR_SYSTEM, NARRATOR_USER_TEMPLATE,
    PERMISSION_EXPLAINER_SYSTEM, PERMISSION_EXPLAINER_USER_TEMPLATE,
    THREAT_CLASSIFIER_SYSTEM
)
from multi_api_client import ask_ai

load_dotenv()

# Keep this shim so report_generator.py (which imports call_gemini) still works
def call_gemini(system_prompt: str, user_prompt: str, json_mode: bool = False) -> str:
    """Backward-compat shim — now routes through the full multi-API cascade."""
    return ask_ai(system_prompt, user_prompt, json_mode=json_mode)



class AINarrator:
    def __init__(self):
        self.narration_history = []

    def narrate_events(self, events: list, is_final: bool = False) -> str:
        """
        Take a batch of threat events and generate
        a real-time security narration.
        """
        if not events:
            return None

        # Simplify events for the prompt
        simplified = [
            {
                "app": e.get("app", "unknown"),
                "type": e.get("type", "unknown"),
                "description": e.get("description", ""),
                "severity": e.get("severity", "LOW"),
                "timestamp": e.get("timestamp", ""),
                "justification": e.get("justification", ""),
                "historical": e.get("historical", False),
                "flags": e.get("flags", [])
            }
            for e in events[:5]  # Max 5 events per narration
        ]

        if is_final:
            user_msg = f"SCAN COMPLETE. Here is the batch of suspicious events:\n{json.dumps(simplified)}\nProvide a FINAL FORENSIC VERDICT for the device security posture. Be extremely actionable."
        else:
            user_msg = NARRATOR_USER_TEMPLATE.format(events_json=json.dumps(simplified, indent=2))

        try:
            narration = ask_ai(
                system_prompt=NARRATOR_SYSTEM,
                user_prompt=user_msg,
                json_mode=False
            )

            self.narration_history.append({
                "narration": narration,
                "timestamp": datetime.now().isoformat(),
                "event_count": len(events),
                "is_final": is_final
            })
            return narration

        except Exception as e:
            print(f"[-] AI Narration fallback triggered: {e}")
            return self._local_briefing(events)

    def _local_briefing(self, events: list) -> str:
        """Generate a local analyst briefing without Claude API."""
        if not events:
            return "Monitoring active. No threats detected yet."
        
        critical = [e for e in events if e.get('severity') == 'CRITICAL']
        high = [e for e in events if e.get('severity') == 'HIGH']
        top_app = max(events, key=lambda x: x.get('threat_score', 0))
        
        parts = []
        
        if critical:
            parts.append(f"CRITICAL ALERT — {len(critical)} critical threat(s) detected.")
        
        parts.append(f"Highest risk: {top_app.get('app','unknown')} (Score {top_app.get('threat_score',0)}/100).")
        
        if high:
            parts.append(f"{len(high)} high-severity events flagged.")
        
        parts.append(f"Monitoring {len(set(e.get('app') for e in events))} apps across {len(events)} events.")
        
        combo = top_app.get('combo_triggered')
        if combo == 'COVERT_RECORDING':
            parts.append("Background recording detected. Immediate review advised.")
        elif combo == 'PAYMENT_INTERCEPT':
            parts.append("Activity during payment detected. High fraud risk.")
        elif combo == 'SLEEP_HOUR_CONTROL':
            parts.append("Night-hour device access detected. Possible remote control.")
        elif combo == 'DATA_EXFILTRATION':
            parts.append("Data upload after sensor access. Possible data leak.")
        
        return " ".join(parts)

    def explain_permission(self, app_name: str, permissions: list) -> str:
        """
        Explain why a specific app's permissions are dangerous.
        """
        try:
            user_prompt = PERMISSION_EXPLAINER_USER_TEMPLATE.format(
                app_name=app_name,
                permissions=", ".join(permissions)
            )
            return call_gemini(
                system_prompt=PERMISSION_EXPLAINER_SYSTEM,
                user_prompt=user_prompt,
                json_mode=False
            )
        except Exception as e:
            print(f"[-] Permission explainer error: {e}")
            return f"{app_name} has {len(permissions)} dangerous permissions."

    def classify_log_line(self, log_line: str) -> dict:
        """
        Use Gemini to classify a raw logcat line.
        Returns structured threat classification.
        """
        try:
            raw = call_gemini(
                system_prompt=THREAT_CLASSIFIER_SYSTEM,
                user_prompt=f"Classify this logcat line:\n{log_line}",
                json_mode=True
            )
            return json.loads(raw)
        except Exception:
            return {"suspicious": False, "severity": "BENIGN"}

    def get_ai_verdict(self, behavior_pattern: dict) -> dict:
        """
        Use Gemini to provide a real intelligent verdict of behavior combos.
        """
        prompt = (
            "You are a mobile security expert AI for PhantomDroid.\n"
            "You receive Android app behavior patterns and determine if they\n"
            "are genuine privacy threats or legitimate app behavior.\n"
            "Be accurate — do not flag legitimate apps.\n"
            "Key signals: screen was OFF = suspicious. Payment app was open = critical.\n"
            "Night hours with idle phone = stalkerware indicator.\n"
            "Multiple sensors at once = profiling attempt.\n"
            "Respond ONLY in this JSON format:\n"
            "{\n"
            "  \"verdict\": \"MALICIOUS or SUSPICIOUS or LEGITIMATE\",\n"
            "  \"confidence\": 0-100,\n"
            "  \"explanation\": \"max 2 sentences in plain English\",\n"
            "  \"recommendation\": \"what user should do right now\"\n"
            "}"
        )
        
        user_message = (
            f"App: {behavior_pattern.get('app')}\n"
            f"Combo detected: {behavior_pattern.get('combo_triggered')}\n"
            f"Permissions used: {behavior_pattern.get('permissions_involved')}\n"
            f"Context: screen_on={behavior_pattern.get('context', {}).get('screen_on')}, "
            f"call_active={behavior_pattern.get('context', {}).get('call_active')}, "
            f"financial_app_open={behavior_pattern.get('context', {}).get('financial_app_open')}, "
            f"is_night={behavior_pattern.get('context', {}).get('is_night')}, "
            f"foreground_app={behavior_pattern.get('context', {}).get('foreground_app')}\n"
            f"Time: {behavior_pattern.get('timestamp')}\n"
            "Is this a genuine privacy threat?"
        )
        try:
            raw = call_gemini(
                system_prompt=prompt,
                user_prompt=user_message,
                json_mode=True
            )
            return json.loads(raw)
        except Exception as e:
            print(f"[-] AI Verdict error: {e}")
            return {
                "verdict": "SUSPICIOUS",
                "confidence": 70,
                "explanation": "Could not fetch AI verdict due to an error.",
                "recommendation": "Review manually."
            }
