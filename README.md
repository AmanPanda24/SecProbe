# 🛡️ SecProbe

AI-Assisted Web Security Misconfiguration Scanner

> Developed by Aman Kumar Panda | Version 1.0.0 | 100% Free AI — No paid keys required

---

## 🤖 Free AI Providers

SecProbe supports three AI modes — all completely free:

| Provider | Speed | Limits | Key Required |
|---|---|---|---|
| Google Gemini Flash | Fast | 1,500 req/day free | ✅ Free key |
| Groq LLaMA 3 | Ultra-fast | 14,400 req/day free | ✅ Free key |
| Offline Engine | Instant | Unlimited | ❌ No key needed |

Get your free key (takes 30 seconds):
- Gemini → https://aistudio.google.com/app/apikey
- Groq   → https://console.groq.com/keys

> No key at all ? Just use `--ai` anyway — the offline engine activates automatically with full explanations and risk scores.

---

## ⚡ Quick Install (Kali Linux)

```bash
git clone https://github.com/349100/secprobe.git
cd secprobe
chmod +x install.sh
sudo ./install.sh


---

## 🖥️ CLI Usage

bash

secprobe example.com

secprobe example.com --ai

export GEMINI_API_KEY=your_free_key
secprobe example.com --ai

export GROQ_API_KEY=your_free_key
secprobe example.com --ai

secprobe example.com --ports --ai --verbose

secprobe example.com --ai --output report.json

secprobe example.com --ai --gemini-key YOUR_KEY
secprobe example.com --ai --groq-key YOUR_KEY


### CLI Output Example

```
  01. [HIGH] Missing Content-Security-Policy [gemini]
      Category : HTTP Headers
      Fix: add_header Content-Security-Policy "default-src 'self'";

  02. [HIGH] Missing Strict-Transport-Security [offline]
      Category : HTTP Headers
      Fix: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

  ──────────────────────────────────────────────────────────────
  Target  : https://example.com
  Score   : 74/100  (Grade: C)
  Issues  : 5 found  |  Scan time: 1.87s
  Summary : Critical:0  High:2  Medium:2  Low:1  Info:0


---

## 🔌 REST API

## Start the API Server

   bash
# Direct
secprobe-api

# As systemd service
sudo systemctl start secprobe-api
sudo systemctl enable secprobe-api

# Docker
docker-compose up -d
```

 Scan Endpoint

   bash
 Basic scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

 With AI (uses whichever free provider is configured)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "use_ai": true}'

  With port scan + AI
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_ports": true, "use_ai": true}'
```

### API Response

```json
{
  "target": "https://example.com",
  "score": 74,
  "grade": "C",
  "scan_time_seconds": 1.87,
  "total_issues": 5,
  "summary": { "critical": 0, "high": 2, "medium": 2, "low": 1, "info": 0 },
  "issues": [
    {
      "type": "Missing Content-Security-Policy",
      "severity": "High",
      "category": "HTTP Headers",
      "impact": "Allows XSS attacks and data injection.",
      "fix": "Add a Content-Security-Policy header.",
      "ai_impact": "Your site has no rules about which scripts can run, so attackers can inject malicious code that steals user data.",
      "ai_fix": "nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\";",
      "risk_score": 7.5,
      "ai_provider": "gemini"
    }
  ]
}
```

---

## ⚙️ Configuration

### Set free API keys

```bash
nano /opt/secprobe/.env
```

```env
 Free Gemini key (https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=your_key_here

 Free Groq key (https://console.groq.com/keys)
GROQ_API_KEY=your_key_here

 API server settings
SECPROBE_HOST=0.0.0.0
SECPROBE_PORT=5000

 Optional: protect the REST API
 SECPROBE_API_KEY=my_secret_key
```

### Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `GEMINI_API_KEY` | — | Google Gemini free API key |
| `GROQ_API_KEY` | — | Groq free API key |
| `SECPROBE_API_KEY` | — | Optional REST API protection key |
| `SECPROBE_HOST` | `0.0.0.0` | API bind address |
| `SECPROBE_PORT` | `5000` | API port |
| `SECPROBE_DEBUG` | `false` | Flask debug mode |

---

## 🏗️ Architecture

```
secprobe/
├── secprobe/
│   ├── scanner.py            ← Core engine & orchestrator
│   ├── cli.py                ← Click CLI (colored terminal output)
│   ├── api.py                ← Flask REST API
│   └── modules/
│       ├── headers.py        ← HTTP security headers scanner
│       ├── ssl_checker.py    ← SSL/TLS cert & config checker
│       ├── port_scanner.py   ← Port exposure (nmap + socket fallback)
│       └── ai_explainer.py   ← Free AI: Gemini / Groq / Offline
├── tests/test_secprobe.py    ← Pytest test suite
├── install.sh                ← Kali Linux one-command installer
├── uninstall.sh
├── Dockerfile
├── docker-compose.yml
├── .env.example              ← Configuration template
├── setup.py
└── requirements.txt
```

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## 🐳 Docker

   bash
docker-compose up -d

GEMINI_API_KEY=your_key docker-compose up -d


---

## 📊 Scoring System

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | A | Excellent |
| 75–89 | B | Good |
| 60–74 | C | Fair |
| 40–59 | D | Poor |
| 0–39 | F | Critical |

Deductions: Critical −25 · High −15 · Medium −8 · Low −3

---

## ⚠️ Legal Disclaimer

Only scan systems you own or have explicit written permission to test.

---

## 👤 Author

Aman Kumar Panda

## 📄 License

MIT License
