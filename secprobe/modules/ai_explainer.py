"""
SecProbe - AI Explanation Layer (Free API Edition)
Three provider options - all free:

  1. Google Gemini   — 15 req/min, 1,500/day FREE
                       Get key: https://aistudio.google.com/app/apikey
  2. Groq            — 30 req/min, 14,400/day FREE (LLaMA 3)
                       Get key: https://console.groq.com/keys
  3. Offline Engine  — No key needed, works 100% locally

Author: Aman Kumar Panda
"""

import json
import urllib.request

SYSTEM_PROMPT = (
    "You are a senior web security expert. Enrich the given security scan findings "
    "with clear, beginner-friendly explanations. "
    "For each issue: (1) rewrite impact in plain English 1-2 sentences, "
    "(2) provide an actionable fix with a code example where possible, "
    "(3) assign a risk_score float 0.0-10.0. "
    "Add fields: ai_impact, ai_fix, risk_score. "
    "Do NOT change existing fields. Return ONLY a raw JSON array, no markdown."
)

OFFLINE_RISK_SCORES = {
    "Critical": 9.5, "High": 7.5, "Medium": 5.0, "Low": 2.5, "Info": 1.0,
}

OFFLINE_AI_IMPACTS = {
    "Missing Content-Security-Policy": "Your site has no rules about which scripts can run, so attackers can inject malicious code that steals user data.",
    "Missing Strict-Transport-Security": "Without HSTS, browsers might connect over plain HTTP first, letting attackers intercept or modify your traffic.",
    "Missing X-Frame-Options": "Your pages can be embedded inside an attacker iframe, tricking users into clicking invisible buttons (clickjacking).",
    "Missing X-Content-Type-Options": "Browsers may guess the wrong file type and execute uploaded files as scripts, enabling XSS attacks.",
    "Missing Referrer-Policy": "Your full page URLs leak to every external site users visit from your pages, exposing sensitive paths.",
    "Missing Permissions-Policy": "Scripts on your site can freely access camera, microphone, or location without explicit permission.",
    "Missing X-XSS-Protection": "Older browsers lack built-in XSS filtering that this header would activate.",
    "Cookie Missing Secure Flag": "Session cookies can be sent over unencrypted HTTP and intercepted by attackers on the same network.",
    "Cookie Missing HttpOnly Flag": "JavaScript can read your session cookies, so any XSS vulnerability lets attackers steal sessions instantly.",
    "Cookie Missing SameSite Attribute": "Cookies are sent automatically with cross-site requests, enabling CSRF attacks that perform actions as the victim.",
    "Invalid SSL Certificate": "Your SSL certificate is not trusted. Browsers show scary warnings and attackers can intercept all traffic.",
    "Expired SSL Certificate": "Your certificate expired. All visitors see security warnings and connections may be blocked by browsers.",
    "Weak Protocol": "Your server accepts old TLS versions with known vulnerabilities that allow attackers to decrypt traffic.",
    "Weak Cipher": "The encryption algorithm used is outdated and can be cracked, exposing encrypted communications.",
    "Open Port": "This service is exposed to the internet when it should be restricted, increasing your attack surface.",
    "Header Disclosure": "Your server reveals its software version, giving attackers a head start in finding matching exploits.",
    "HTTPS Not Available": "Your site has no encryption at all. All passwords and data users send are visible to anyone on the network.",
    "Connection Failed": "SecProbe could not reach your site. Either it is offline, blocking scans, or the URL is wrong.",
}

OFFLINE_AI_FIXES = {
    "Missing Content-Security-Policy": "nginx: add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'\";\nApache: Header set Content-Security-Policy \"default-src 'self'\"",
    "Missing Strict-Transport-Security": "nginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\nApache: Header always set Strict-Transport-Security \"max-age=31536000\"",
    "Missing X-Frame-Options": "nginx: add_header X-Frame-Options \"DENY\";\nApache: Header set X-Frame-Options \"DENY\"",
    "Missing X-Content-Type-Options": "nginx: add_header X-Content-Type-Options \"nosniff\";\nApache: Header set X-Content-Type-Options \"nosniff\"",
    "Missing Referrer-Policy": "nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\";\nApache: Header set Referrer-Policy \"strict-origin-when-cross-origin\"",
    "Missing Permissions-Policy": "nginx: add_header Permissions-Policy \"geolocation=(), camera=(), microphone=()\";\nApache: Header set Permissions-Policy \"geolocation=(), camera=()\"",
    "Cookie Missing Secure Flag": "Flask: response.set_cookie('name', 'value', secure=True)\nPHP: setcookie('name', 'value', ['secure' => true])\nnginx: proxy_cookie_flags ~ secure;",
    "Cookie Missing HttpOnly Flag": "Flask: response.set_cookie('name', 'value', httponly=True)\nPHP: setcookie('name', 'value', ['httponly' => true])",
    "Cookie Missing SameSite Attribute": "Flask: response.set_cookie('name', 'value', samesite='Strict')\nPHP: setcookie('name', 'value', ['samesite' => 'Strict'])",
    "Expired SSL Certificate": "Renew free with Let's Encrypt:\n  sudo certbot renew\n  sudo certbot --nginx -d yourdomain.com",
    "Invalid SSL Certificate": "sudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com",
    "Weak Protocol": "nginx.conf: ssl_protocols TLSv1.2 TLSv1.3;\nApache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
    "Weak Cipher": "nginx: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;\n  ssl_prefer_server_ciphers off;",
    "Open Port 22": "sudo ufw allow from YOUR_IP to any port 22\nsudo ufw deny 22\n/etc/ssh/sshd_config: PasswordAuthentication no",
    "Open Port 3306": "/etc/mysql/mysql.conf.d/mysqld.cnf: bind-address = 127.0.0.1\nsudo systemctl restart mysql",
    "Open Port 6379": "/etc/redis/redis.conf: bind 127.0.0.1\nrequirepass YourStrongPassword\nsudo systemctl restart redis",
    "Header Disclosure: Server": "nginx: server_tokens off;\nApache: ServerTokens Prod\nServerSignature Off",
    "Header Disclosure: X-Powered-By": "PHP php.ini: expose_php = Off\nExpress: app.disable('x-powered-by')\nnginx: proxy_hide_header X-Powered-By;",
    "HTTPS Not Available": "sudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com\nsudo systemctl reload nginx",
}


def _match(table: dict, issue_type: str, default: str) -> str:
    for key, val in table.items():
        if key.lower() in issue_type.lower() or issue_type.lower() in key.lower():
            return val
    return default


def _parse(raw: str, original: list) -> list:
    raw = raw.strip()
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
    try:
        parsed = json.loads(raw.strip())
        return parsed if isinstance(parsed, list) else original
    except Exception:
        return original


class GeminiExplainer:
    """Google Gemini Flash - FREE (1,500 req/day). Key: https://aistudio.google.com/app/apikey"""
    URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"

    def __init__(self, api_key):
        self.api_key = api_key

    def enrich(self, issues):
        payload = json.dumps({
            "contents": [{"parts": [{"text": f"{SYSTEM_PROMPT}\n\n{json.dumps(issues, indent=2)}"}]}],
            "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096},
        }).encode()
        req = urllib.request.Request(f"{self.URL}?key={self.api_key}", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read().decode())
            return _parse(res["candidates"][0]["content"]["parts"][0]["text"], issues)


class GroqExplainer:
    """Groq LLaMA 3 - FREE (14,400 req/day, ultra fast). Key: https://console.groq.com/keys"""
    URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, api_key):
        self.api_key = api_key

    def enrich(self, issues):
        payload = json.dumps({
            "model": "llama3-8b-8192",
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(issues, indent=2)},
            ],
            "temperature": 0.3, "max_tokens": 4096,
        }).encode()
        req = urllib.request.Request(self.URL, data=payload, headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        })
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.loads(r.read().decode())
            return _parse(res["choices"][0]["message"]["content"], issues)


class OfflineExplainer:
    """Built-in rule engine - NO API KEY needed. Works completely offline."""

    def enrich(self, issues):
        result = []
        for issue in issues:
            copy = dict(issue)
            t = issue.get("type", "")
            copy["ai_impact"] = _match(OFFLINE_AI_IMPACTS, t, f"This misconfiguration increases vulnerability to attacks.")
            copy["ai_fix"] = _match(OFFLINE_AI_FIXES, t, f"Review: https://owasp.org/www-project-secure-headers/")
            copy["risk_score"] = OFFLINE_RISK_SCORES.get(issue.get("severity", "Info"), 1.0)
            copy["ai_provider"] = "offline"
            result.append(copy)
        return result


class AIExplainer:
    """
    Auto-selects best available free AI provider.

    Priority: Gemini → Groq → Offline (no key fallback)

    Free API Keys (takes 30 seconds to get):
      Gemini: https://aistudio.google.com/app/apikey
      Groq:   https://console.groq.com/keys
    """

    def __init__(self, gemini_key: str = None, groq_key: str = None):
        self.gemini_key = gemini_key
        self.groq_key = groq_key

    @property
    def active_provider(self) -> str:
        if self.gemini_key:
            return "gemini (free)"
        if self.groq_key:
            return "groq (free)"
        return "offline (no key)"

    def enrich(self, issues: list) -> list:
        if not issues:
            return issues

        if self.gemini_key:
            try:
                result = GeminiExplainer(self.gemini_key).enrich(issues)
                if result and result != issues:
                    for r in result:
                        r.setdefault("ai_provider", "gemini")
                    return result
            except Exception:
                pass

        if self.groq_key:
            try:
                result = GroqExplainer(self.groq_key).enrich(issues)
                if result and result != issues:
                    for r in result:
                        r.setdefault("ai_provider", "groq")
                    return result
            except Exception:
                pass

        return OfflineExplainer().enrich(issues)
