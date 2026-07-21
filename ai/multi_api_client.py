"""
PhantomDroid — Multi-API Load-Balanced Client
Cascades through free/cheap AI providers in order.
If one hits a rate limit or fails, it falls forward to the next.

Priority order (fastest / cheapest first):
  1. Groq         — llama-3.3-70b-versatile  (fastest, very generous free tier)
  2. Cerebras     — llama-3.3-70b            (hardware-accelerated, free tier)
  3. OpenRouter   — qwen/qwen-2.5-coder-32b  (Qwen free via OpenRouter)
  4. Gemini       — gemini-1.5-flash         (Google free tier, direct REST)

Add your keys to .env file — any key that is missing or blank is skipped.
"""

import os
import json
import urllib.request
import urllib.error
from dotenv import load_dotenv

load_dotenv()

# ── Provider definitions ──────────────────────────────────────────────────────
# All OpenAI-compatible providers share the same client interface.
# Gemini uses its own REST format and is handled separately.
OPENAI_PROVIDERS = [
    {
        "name": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
    },
    {
        "name": "Cerebras",
        "base_url": "https://api.cerebras.ai/v1",
        "api_key_env": "CEREBRAS_API_KEY",
        "model": "llama-3.3-70b",
    },
    {
        "name": "OpenRouter (Qwen)",
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "model": "qwen/qwen-2.5-coder-32b:free",
    },
]

# ── OpenAI-compatible call ────────────────────────────────────────────────────
def _call_openai_provider(provider: dict, system_prompt: str, user_prompt: str) -> str:
    """Calls any OpenAI-compatible endpoint."""
    import openai  # Already installed (v2.44+)

    api_key = os.getenv(provider["api_key_env"], "").strip()
    if not api_key or "your_" in api_key:
        raise ValueError(f"Key not set for {provider['name']}")

    client = openai.OpenAI(
        base_url=provider["base_url"],
        api_key=api_key,
    )

    response = client.chat.completions.create(
        model=provider["model"],
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        timeout=20.0,
        max_tokens=1024,
    )
    return response.choices[0].message.content.strip()


# ── Gemini REST fallback ──────────────────────────────────────────────────────
def _call_gemini(system_prompt: str, user_prompt: str, json_mode: bool = False) -> str:
    """Direct Google Gemini REST call (no SDK needed)."""
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key or "your_" in api_key:
        raise ValueError("GEMINI_API_KEY not set")

    url = (
        f"https://generativelanguage.googleapis.com/v1beta"
        f"/models/gemini-1.5-flash:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
    }
    if json_mode:
        payload["generationConfig"] = {"responseMimeType": "application/json"}

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()


# ── Main public function ──────────────────────────────────────────────────────
def ask_ai(
    system_prompt: str,
    user_prompt: str,
    json_mode: bool = False,
) -> str:
    """
    Public entry point. Tries each provider in priority order.
    Falls through to the next on any error (rate limit, missing key, timeout).

    Args:
        system_prompt: The system / role instruction for the AI.
        user_prompt:   The actual question or task.
        json_mode:     If True, instructs the model to return pure JSON.

    Returns:
        A plain-text (or JSON string) response from the first successful provider.

    Raises:
        RuntimeError if ALL providers fail.
    """
    errors = []

    # 1. Try OpenAI-compatible providers first (Groq → Cerebras → OpenRouter)
    for provider in OPENAI_PROVIDERS:
        try:
            print(f"[AI] Trying {provider['name']}...")
            result = _call_openai_provider(provider, system_prompt, user_prompt)
            print(f"[AI] Success via {provider['name']}")
            return result
        except ValueError as e:
            # Key not configured — skip silently
            errors.append(f"{provider['name']}: {e}")
        except Exception as e:
            print(f"[AI] {provider['name']} failed: {e} — trying next...")
            errors.append(f"{provider['name']}: {e}")

    # 2. Fallback to Gemini REST
    try:
        print("[AI] Trying Gemini REST...")
        result = _call_gemini(system_prompt, user_prompt, json_mode=json_mode)
        print("[AI] Success via Gemini")
        return result
    except ValueError as e:
        errors.append(f"Gemini: {e}")
    except Exception as e:
        print(f"[AI] Gemini failed: {e}")
        errors.append(f"Gemini: {e}")

    # 3. All providers failed
    raise RuntimeError(
        f"All AI providers failed or keys not set.\nDetails:\n" + "\n".join(errors)
    )
