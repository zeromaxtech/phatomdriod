# 👻 PhantomDroid V3 — Personal Privacy Guardian

> **The million dollar question everyone asks: "Is Instagram listening to my conversations?"**
> PhantomDroid answers it with PROOF and DATA.

PhantomDroid monitors your Android phone via USB cable from your laptop, detects microphone access, network calls to ad servers, and correlates them to prove whether apps are targeting you with ads based on your conversations.

---

## 🏗️ Architecture

```
Your Laptop                          Your Android Phone
┌──────────────────────────┐              │
│  Flask Backend (port 5000)│◄── USB ─────┤ USB Debugging ON
│  Python ADB Engine        │             │
│  SQLite local storage     │             │
│  Ollama local AI          │             │
│  Multi-provider AI API    │             │
│  Web Dashboard            │             │
└──────────────────────────┘             │
```

## 🎯 3 Monitoring Modes

| Mode | What It Does | Duration |
|------|-------------|---------|
| 🕐 **24HR WATCH** | Silent background monitoring, full daily report | 24 hours |
| ⚡ **QUICK SCAN** | Deep scan right now, instant results | 3 minutes |
| 👁 **LIVE WATCH** | Put Instagram/YouTube under a microscope in real time | Until stopped |

## 📡 Ad Profiling Detection

The killer feature — catches mic → ad server correlation:

```
9:43 PM → Instagram accessed MICROPHONE 🔴
9:43 PM (4 seconds later) → Google Ad Services contacted
→ PROBABILITY: HIGH (65-85%)
```

---

## 🚀 Quick Start (Local)

### Prerequisites
- Python 3.10+
- Android phone with **USB Debugging enabled**
- ADB (Android Debug Bridge)
- MySQL (optional — falls back to SQLite automatically)

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/phantomdroid.git
cd phantomdroid

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy and fill in your API keys
copy .env.example .env
# Edit .env with your keys

# 4. Connect your phone via USB
# Enable USB Debugging: Settings → Developer Options → USB Debugging ON

# 5. Start the backend
python backend/app.py

# 6. Open the dashboard
# → http://localhost:5000
```

### API Keys (add at least ONE)

| Provider | Get Key | Free? |
|----------|---------|-------|
| **Groq** (fastest) | [console.groq.com](https://console.groq.com) | ✅ Free |
| **Gemini** | [aistudio.google.com](https://aistudio.google.com) | ✅ Free |
| **OpenRouter** | [openrouter.ai](https://openrouter.ai) | ✅ Free (Qwen) |
| **Cerebras** | [cloud.cerebras.ai](https://cloud.cerebras.ai) | ✅ Free |

---

## 🌐 Deploy to Railway

```bash
# 1. Push to GitHub
git init
git add .
git commit -m "PhantomDroid V3"
git remote add origin https://github.com/yourusername/phantomdroid.git
git push -u origin main

# 2. Go to railway.app → New Project → Deploy from GitHub
# 3. Add environment variables in Railway dashboard:
#    GEMINI_API_KEY, GROQ_API_KEY, MYSQL_*, etc.
# 4. Railway auto-deploys via the Procfile
```

> **Note:** Railway deployment runs the web dashboard but cannot connect to your phone (no USB). 
> For full functionality, run locally with USB cable.

---

## 📁 Project Structure

```
phantomdroid/
├── backend/
│   ├── app.py              # Flask app entry point
│   ├── db.py               # MySQL connector
│   └── routes/
│       ├── scan.py         # Scan/monitor API endpoints
│       └── report.py       # PDF report generation
├── engine/
│   ├── adb_engine.py       # ADB connection & quick scan
│   ├── background_monitor.py # 24hr/quick/live monitor daemon
│   ├── ad_correlation.py   # Mic→ad server correlation engine
│   ├── sqlite_store.py     # Local SQLite storage
│   ├── ollama_analyst.py   # Local AI via Ollama
│   ├── threat_analyzer.py  # Logcat threat detection
│   ├── adb_utils.py        # Shared ADB path resolver
│   ├── firebase_pusher.py  # Real-time Firebase push
│   └── virustotal_check.py # APK malware check
├── ai/
│   ├── multi_api_client.py # Multi-provider AI cascade
│   ├── narrator.py         # Live AI narration
│   ├── report_generator.py # PDF report AI content
│   └── prompts.py          # System prompts
├── frontend/
│   └── index.html          # Full dashboard (single file)
├── data/                   # SQLite DB stored here (gitignored)
├── .env                    # Your API keys (gitignored)
├── requirements.txt
└── Procfile                # Railway deployment
```

---

## 🤖 AI Providers (Auto-cascade)

The app tries providers in order — if one fails or has no key, it automatically tries the next:

1. **Groq** → `llama-3.3-70b-versatile` (fastest)
2. **Cerebras** → `llama-3.3-70b`
3. **OpenRouter** → `qwen/qwen-2.5-coder-32b:free`
4. **Gemini** → `gemini-1.5-flash` (fallback)

---

## 📊 Known Ad Servers Monitored

`googleadservices.com` · `doubleclick.net` · `facebook.com/tr` · `googlesyndication.com` · `amazon-adsystem.com` · `scorecardresearch.com` · `taboola.com` · `appsflyer.com` · `adjust.com` · and more

---

## 📱 Apps Profiled

Instagram · YouTube · Facebook · Netflix · Spotify · Chrome · Google Search · TikTok · Snapchat

---

## ⚠️ Disclaimer

PhantomDroid is a security research and privacy awareness tool.
Only monitor devices you own or have explicit permission to monitor.
