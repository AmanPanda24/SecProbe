# 🛡️ SecProbe

AI-Assisted Web Security Misconfiguration Scanner

> Developed by Aman Kumar Panda | Version 1.0.0 | 100% Free AI — No paid keys required

---

## 🧭 What SecProbe Is (and Isn't)

SecProbe is a **configuration and hygiene scanner**, not a full vulnerability scanner. Its core is checking whether a target has the security-relevant settings it *should* have — headers, cookie flags, TLS config, obviously risky open ports. As of this version it also does **optional, best-effort CVE matching** against banner-advertised software versions (see caveats below). It does not send exploit payloads and does not attempt to actively break anything. If you're used to tools like Nessus, Nuclei, or OWASP ZAP, SecProbe still sits in a narrower category — closer to Mozilla Observatory or SSL Labs' SSL Test with a version-fingerprinting layer bolted on, rather than a full active vulnerability scanner.

Being upfront about this matters more to us than the marketing appeal of a bigger label. A misconfig scanner that's honest about its scope is more useful — and more trustworthy — than a "vulnerability scanner" that quietly only checks headers.

### How it compares

| Capability | SecProbe | Nessus / OpenVAS / Qualys | Nikto | Nuclei | OWASP ZAP |
|---|---|---|---|---|---|
| HTTP security header audit | ✅ core focus | partial | partial | via community templates | partial |
| Cookie flag audit (Secure/HttpOnly/SameSite) | ✅ | partial | ❌ | via templates | ✅ |
| SSL/TLS config check (protocol, cipher, expiry, SAN) | ✅ | ✅ | ❌ | via templates | ❌ |
| Common risky port exposure check | ✅ (static list) | ✅ (extensive) | ❌ | ❌ | ❌ |
| Software/version fingerprinting → CVE matching | ⚠️ opt-in, banner-based only (`--cve`) | ✅ (large, maintained DB, deeper detection) | basic | ✅ (community-driven) | limited |
| Active exploit probing (SQLi, XSS, SSRF, RCE payloads) | ❌ | ✅ | basic | ✅ | ✅ (core focus, incl. proxy/fuzzer) |
| Authenticated / crawled deep scanning | ❌ | ✅ | ❌ | some | ✅ |
| Plain-English, beginner-friendly explanations | ✅ (AI layer) | ❌ (dense, expert-oriented) | ❌ | ❌ | ❌ |
| Setup cost | free, single CLI command | commercial, or heavy self-hosted server (OpenVAS) | free, lightweight | free, lightweight | free, heavier GUI/proxy setup |
| Typical scan time (single host) | under a few seconds (longer with `--cve`, due to NVD rate limits) | minutes to hours | seconds to minutes | seconds to minutes | minutes (interactive) |

### Where SecProbe genuinely adds value

- **Explains findings in plain language, with copy-paste fixes.** The AI layer (Gemini / Groq / offline rule engine) turns a raw header-diff into "here's what this means, here's the nginx/Apache/Flask snippet to fix it" — something the expert-oriented output of Nessus or OpenVAS doesn't prioritize.
- **Zero setup friction.** No account, no license, no heavyweight scan engine to stand up — one command, results in under a second for a header+SSL scan.
- **Good as a fast first pass or a CI/CD gate**, e.g. failing a build if a new deploy drops HSTS or exposes a database port — not as a replacement for a real penetration test or an authenticated deep scan.

### ⚠️ CVE Matching (`--cve`) — read this before you trust the output

This mode reads whatever version string a server *volunteers* in headers like `Server` and `X-Powered-By`, and cross-references it against the official [NVD](https://nvd.nist.gov/) database. It is **not** equivalent to what Nessus/OpenVAS do:

- **Banner-based only.** No behavioral fingerprinting, no probing — just reading what the server advertises. Many servers strip or fake this header deliberately; reverse proxies and CDNs frequently rewrite it. A missing or generic banner means zero CVE findings, not a clean bill of health.
- **Keyword-matched, not CPE-matched.** SecProbe uses NVD's free-text `keywordSearch`, not a precise CPE lookup, so it filters for CVEs whose advisory text actually mentions the detected version — anything that doesn't match is labeled `loosely matched` rather than silently hidden or silently trusted.
- **Every finding needs manual verification.** Treat `--cve` output as "worth checking," not "confirmed vulnerable." This is explicitly reflected in the fix text on every CVE issue it raises.
- **Rate-limited by NVD.** Without a free API key, NVD allows 5 requests/30s, so a `--cve` scan with several detected components will take longer. Get a free key at https://nvd.nist.gov/developers/request-an-api-key and pass it via `--nvd-key` or the `NVD_API_KEY` env var for higher throughput.

### What it still deliberately doesn't do

- No active payload testing for SQLi/XSS/SSRF/etc. — it won't try to break the target, only audit its declared configuration and publicly known CVEs against what it advertises.
- No authenticated or crawled scanning of application logic.
- No CPE-precise vulnerability matching — see the CVE caveats above.

If any of the above get added later, this README will be updated to reflect that rather than claiming it upfront.

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

secprobe example.com --cve

export NVD_API_KEY=your_free_nvd_key
secprobe example.com --cve --verbose

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

 With CVE matching (banner-based, best-effort — see README caveats)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "check_cve": true}'
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
| `NVD_API_KEY` | — | Optional free NVD key for higher rate limits during `--cve` scans |
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
│       ├── version_fingerprint.py  ← Banner-based version detection + NVD CVE matching (opt-in, --cve)
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
