# 🛡️ SecProbe

Nikto-inspired Web Security Scanner with AI-assisted analysis

> Developed by Aman Kumar Panda | Version 1.0.0 | 100% Free AI (No paid keys required).

---

## 🧭 What SecProbe Is (and Isn't)

SecProbe is a **configuration and hygiene scanner**, not a full vulnerability scanner. Its core is checking whether a target has the security relevant settings it *should* have headers, cookie flags, TLS config, obviously risky open ports plus a set of Nikto-style, non-exploitative reconnaissance checks (common exposed paths, HTTP methods, CORS, directory listing, technology fingerprinting). As of this version it also does **optional, best-effort CVE matching** against banner-advertised software versions (see caveats below). It does not send exploit payloads and does not attempt to actively break anything.

If you're used to tools like Nessus, Nuclei, or OWASP ZAP, SecProbe still sits in a narrower category closer to Nikto or Mozilla Observatory/SSL Labs' SSL Test with a version-fingerprinting layer bolted on, rather than a full active vulnerability scanner.

Being upfront about this matters more to us than the marketing appeal of a bigger label. A misconfig scanner that's honest about its scope is more useful and more trustworthy than a "vulnerability scanner" that quietly only checks headers.

### How it compares

| Capability | SecProbe | Nessus / OpenVAS / Qualys | Nikto | Nuclei | OWASP ZAP |
|---|---|---|---|---|---|
| HTTP security header audit | ✅ core focus | partial | partial | via community templates | partial |
| Cookie flag audit (Secure/HttpOnly/SameSite) | ✅ | partial | ❌ | via templates | ✅ |
| SSL/TLS config check (protocol, cipher, expiry, SAN) | ✅ | ✅ | ❌ | via templates | ❌ |
| Common risky port exposure check | ✅ (static list) | ✅ (extensive) | ❌ | ❌ | ❌ |
| Common exposed path / sensitive file discovery (`.env`, `.git`, backups, admin/diagnostic pages) | ✅ (with soft-404 baseline filtering) | ✅ | ✅ core focus | via templates | some |
| HTTP method / CORS / directory-listing / verbose-error checks | ✅ | partial | ✅ | via templates | ✅ |
| Software/version fingerprinting → CVE matching | ⚠️ opt-in, banner-based only (`--cve`) | ✅ (large, maintained DB, deeper detection) | basic | ✅ (community-driven) | limited |
| Active exploit probing (SQLi, XSS, SSRF, RCE payloads) | ❌ | ✅ | basic | ✅ | ✅ (core focus, incl. proxy/fuzzer) |
| Authenticated / crawled deep scanning | ❌ | ✅ | ❌ | some | ✅ |
| Plain-English, beginner-friendly explanations | ✅ (AI layer) | ❌ (dense, expert-oriented) | ❌ | ❌ | ❌ |
| Setup cost | free, single CLI command | commercial, or heavy self-hosted server (OpenVAS) | free, lightweight | free, lightweight | free, heavier GUI/proxy setup |
| Typical scan time (single host) | a few seconds (longer with `--cve`/`--ports`, due to rate limits/probing) | minutes to hours | seconds to minutes | seconds to minutes | minutes (interactive) |

### Where SecProbe genuinely adds value

- **Explains findings in plain language, with copy-paste fixes.** The AI layer (Gemini / Groq / offline rule engine) turns a raw header-diff or exposed-path finding into "here's what this means, here's the nginx/Apache/Flask snippet to fix it."
- **Zero setup friction.** No account, no license, no heavyweight scan engine to stand up one command, results in seconds for a header+SSL+recon scan.
- **False-positive aware.** Common-path discovery (`--no-discover` to skip it) uses a soft-404 baseline check: it first probes a path that shouldn't exist, and only reports a "real" file if the response actually differs from that baseline. This avoids flooding you with false "Critical: database.sql exposed" findings on sites that return HTTP 200 for everything (common with SPAs and custom error pages).
- **Good as a fast first pass or a CI/CD gate**, e.g. failing a build if a new deploy drops HSTS, exposes `.env`, or opens a database port — not as a replacement for a real penetration test or an authenticated deep scan.

### ⚠️ CVE Matching (`--cve`) read this before you trust the output

This mode reads whatever version string a server *volunteers* in headers like `Server` and `X-Powered-By`, and cross-references it against the official [NVD](https://nvd.nist.gov/) database. It is **not** equivalent to what Nessus/OpenVAS do:

- **Banner-based only.** No behavioral fingerprinting, no probing just reading what the server advertises. Many servers strip or fake this header deliberately; reverse proxies and CDNs frequently rewrite it. A missing or generic banner means zero CVE findings, not a clean bill of health.
- **Keyword-matched, not CPE-matched.** SecProbe uses NVD's free-text `keywordSearch`, not a precise CPE lookup, so it filters for CVEs whose advisory text actually mentions the detected version anything that doesn't match is labeled `loosely matched` rather than silently hidden or silently trusted.
- **Every finding needs manual verification.** Treat `--cve` output as "worth checking," not "confirmed vulnerable."
- **Rate-limited by NVD.** Without a free API key, NVD allows 5 requests/30s. Get a free key at https://nvd.nist.gov/developers/request-an-api-key and pass it via `--nvd-key` or the `NVD_API_KEY` env var for higher throughput.

### What it still deliberately doesn't do

- No active payload testing for SQLi/XSS/SSRF/etc. it won't try to break the target, only audit its declared configuration, publicly reachable resources, and publicly known CVEs against what it advertises.
- No authenticated or crawled scanning of application logic.
- No CPE-precise vulnerability matching see the CVE caveats above.

If any of the above get added later, this README will be updated to reflect that rather than claiming it upfront.

---

## 🔎 Nikto-like Scan Profile

SecProbe 1.0 includes non-exploitative web-server/application reconnaissance inspired by the practical workflow of Nikto:

- security header and cookie auditing
- HTTPS/redirect and transport checks, with automatic HTTP↔HTTPS fallback if the target only answers on one scheme
- HTTP method inspection (OPTIONS/TRACE/PUT/DELETE)
- CORS policy checks (wildcard origin, credentials + wildcard, reflected origin)
- technology fingerprinting from public responses (framework/CMS hints, `Server`, `X-Powered-By`)
- common resource discovery (`robots.txt`, `sitemap.xml`, `security.txt`)
- checks for commonly exposed diagnostics, VCS metadata, `.env`, backups and database dumps with a **soft-404 baseline check** so sites that return HTTP 200 for everything don't produce false positives
- directory-listing and verbose-error detection
- optional Nmap port scanning (`--ports`) and banner-based NVD CVE matching (`--cve`)
- AI/offline explanations and remediation

SecProbe does **not** send exploit payloads, brute-force credentials, or attempt to compromise the target. Only scan systems you own or are authorized to assess.

---

## 🤖 Free AI Providers

SecProbe supports three AI modes all completely free:

| Provider | Speed | Limits | Key Required |
|---|---|---|---|
| Google Gemini Flash | Fast | 1,500 req/day free | ✅ Free key |
| Groq LLaMA 3 | Ultra-fast | 14,400 req/day free | ✅ Free key |
| Offline Engine | Instant | Unlimited | ❌ No key needed |

Get your free key (takes 30 seconds):
- Gemini → https://aistudio.google.com/app/apikey
- Groq → https://console.groq.com/keys

No key at all? Just use `--ai` anyway the offline engine activates automatically with full explanations and risk scores.

---

## ⚡ Quick Install (Kali Linux)

```bash
git clone https://github.com/349100/secprobe.git
cd secprobe
chmod +x install.sh
sudo ./install.sh
```

This installs SecProbe into a virtualenv at `/opt/secprobe`, links a `secprobe` command into `/usr/local/bin`, and sets up an optional `secprobe-api` systemd service. To remove it later: `sudo ./uninstall.sh`.

### Manual install (any Linux, no root)

```bash
git clone https://github.com/349100/secprobe.git
cd secprobe
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
secprobe example.com
```

---

## 🖥️ CLI Usage

```bash
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

secprobe example.com --no-discover     # skip Nikto-like path/resource checks, fast header+TLS-only scan
secprobe example.com --timeout 20      # increase HTTP request timeout (default 10s)
secprobe example.com --debug           # print the fetch fingerprint (see Troubleshooting below)
```

### CLI Output Example

```
  01. [HIGH] Missing Content Security Policy [gemini]
      Category : HTTP Headers
      Fix: add_header Content Security Policy "default-src 'self'";

  02. [HIGH] Missing Strict Transport Security [offline]
      Category : HTTP Headers
      Fix: add_header Strict Transport Security "max-age=31536000; includeSubDomains" always;

  ──────────────────────────────────────────────────────────────
  Target  : https://example.com
  Score   : 74/100  (Grade: C)
  Issues  : 5 found  |  Scan time: 1.87s
  Summary : Critical:0  High:2  Medium:2  Low:1  Info:0
```

---

## 🔌 REST API

### Start the API Server

```bash
# Direct
secprobe-api

# As systemd service (after install.sh)
sudo systemctl start secprobe-api
sudo systemctl enable secprobe-api

# Docker
docker-compose up -d
```

### Scan Endpoint

```bash
# Basic scan
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# With AI (uses whichever free provider is configured)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "use_ai": true}'

# With port scan + AI
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_ports": true, "use_ai": true}'

# With CVE matching (banner-based, best-effort — see caveats above)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "check_cve": true}'

# Skip Nikto-like resource discovery (headers + TLS only, fastest)
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "discover": false}'
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
  "scan_profile": {
    "nikto_like": true,
    "active_exploit_testing": false,
    "common_resource_discovery": true,
    "ports": false,
    "cve_banner_matching": false
  },
  "debug": {
    "requested_target": "https://example.com",
    "resolved_hostname": "example.com",
    "final_url_after_redirects": "https://example.com/",
    "status_code": 200,
    "used_https": true,
    "redirect_chain": [],
    "connection_attempts": []
  },
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
# Free Gemini key (https://aistudio.google.com/app/apikey)
GEMINI_API_KEY=your_key_here

# Free Groq key (https://console.groq.com/keys)
GROQ_API_KEY=your_key_here

# API server settings
SECPROBE_HOST=0.0.0.0
SECPROBE_PORT=5000

# Optional: protect the REST API
# SECPROBE_API_KEY=my_secret_key
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
│   ├── scanner.py                  ← Core engine & orchestrator (scheme resolution, TLS gating, scoring)
│   ├── cli.py                      ← Click CLI (colored terminal output, --debug fingerprint)
│   ├── api.py                      ← Flask REST API
│   └── modules/
│       ├── headers.py              ← HTTP security headers + cookie scanner
│       ├── ssl_checker.py          ← SSL/TLS cert & config checker
│       ├── port_scanner.py         ← Port exposure (nmap + socket fallback)
│       ├── version_fingerprint.py  ← Banner-based version detection + NVD CVE matching (opt-in, --cve)
│       ├── web_checks.py           ← Nikto-like checks: paths, methods, CORS, fingerprinting, soft-404 baseline
│       └── ai_explainer.py         ← Free AI: Gemini / Groq / Offline
├── tests/test_secprobe.py          ← Pytest test suite (38 tests)
├── install.sh                      ← Kali Linux one-command installer
├── uninstall.sh
├── Dockerfile
├── docker-compose.yml
├── .env.example                    ← Configuration template
├── setup.py
└── requirements.txt
```

---

## 🩺 Troubleshooting: "I get the same result for every target"

If two clearly different sites produce identical or near-identical results, the scan usually isn't actually reaching the second target. Diagnose with `--debug`:

```bash
secprobe example.com --debug
secprobe github.com --debug
```

Check the `DEBUG FINGERPRINT` block for each run:

- **`Status code` is blank/`None` for every target** → the scan never got a response at all (see `Connection attempts` for the actual error). Check basic connectivity from the machine running SecProbe: `ping 8.8.8.8`, `nslookup example.com`, `curl -v https://example.com`. Common causes on a Kali VM: NAT-mode networking with no route out, missing DNS config, or a proxy/VPN blocking outbound requests.
- **`Requested target`/`Resolved host` don't change between runs** → you're re-running the same command (check your shell history), or a script/alias is hardcoding a target.
- **`Status code` is a real number but every target still looks similar** → this can legitimately happen: many sites share the same missing security headers, so overlapping findings aren't a bug. Compare the actual `issues` list (or `--output report.json` and diff two runs) rather than just the score — the specific findings, `Raw headers`, and `Used HTTPS` value should differ per target even when the overall grade is similar.
- **Every path-discovery finding looks alarming on a specific site (multiple "Critical: exposed" results)** → SecProbe already guards against this with a soft-404 baseline check; if you still see it, that site may be returning genuinely different content per path (worth manually verifying), or you're running an older build — pull the latest version.

---

## 🧪 Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

38 tests cover header/cookie logic, scoring, CVE matching, the AI explainer, the REST API, the Nikto-like `web_checks` module (including the soft-404 baseline filter), and the HTTPS/HTTP scheme-resolution logic in the scanner.

---

## 🐳 Docker

```bash
docker-compose up -d

# with a free AI key
GEMINI_API_KEY=your_key docker-compose up -d
```

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

## 📝 Changelog

### v1.0.0 — Initial Release

- Core scanner: HTTP security header + cookie audit, SSL/TLS certificate and configuration checks, common risky port exposure scanning, banner-based NVD CVE matching (`--cve`), and free AI explanations (Gemini / Groq / offline).
- Nikto-like reconnaissance module (`web_checks.py`): common exposed-path discovery, HTTP method checks, CORS checks, directory-listing/verbose-error detection, and technology fingerprinting - all non-exploitative, read-only requests.
- **Soft-404 baseline detection**: path discovery first probes a nonexistent path and only reports a "real" file if the response actually differs from that baseline, so sites that return HTTP 200 for everything (SPAs, custom error pages) don't produce false "exposed file" findings.
- **Correct HTTPS/HTTP scheme handling**: bare hostnames (`secprobe example.com`) automatically fall back to HTTP if HTTPS fails, and the report's `target` / `debug.used_https` fields reflect what the scanner actually connected with so an HTTP-only host is never mislabeled as HTTPS or given a misleading SSL/TLS check. An explicitly-typed scheme (`http://` or `https://`) is always respected as-is with no fallback.
- `--debug` fingerprint (also in the API's `debug` field) showing requested target, resolved hostname, final URL after redirects, status code, `used_https`, redirect chain, and any connection errors the fastest way to confirm two scans actually hit two different targets.
- `--no-discover` / `discover` flag to skip resource-discovery checks for a fast header+TLS-only scan, and `--timeout` to tune the HTTP request timeout.
- 38-test suite covering every module above, including regression tests for the scheme-handling and soft-404 fixes.

---

## ⚠️ Legal Disclaimer

Only scan systems you own or have explicit written permission to test. SecProbe performs read-only requests and public-resource discovery; it does not attempt to exploit, brute-force, or otherwise compromise a target, but unauthorized scanning of systems you don't own or have permission to test may still violate the law (e.g. the U.S. Computer Fraud and Abuse Act or equivalent local laws) in many jurisdictions.

---

## 👤 Author

Aman Kumar Panda

## 📄 License

MIT License
