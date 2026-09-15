"""Nikto-like passive/light active web checks for SecProbe.

These checks are intentionally non-exploitative: they use normal HTTP requests,
common resource discovery, OPTIONS/HEAD and response inspection. They do not
attempt credential attacks or exploit payloads.
"""
from urllib.parse import urljoin, urlparse
import re
import requests

COMMON_PATHS = [
    ("robots.txt", "Robots.txt", "Info"),
    ("sitemap.xml", "Sitemap", "Info"),
    ("security.txt", "Security.txt", "Info"),
    (".well-known/security.txt", "Security.txt", "Info"),
    ("server-status", "Apache Server Status", "Medium"),
    ("server-info", "Apache Server Info", "Medium"),
    ("phpinfo.php", "PHP Info Page", "High"),
    ("info.php", "PHP Info Page", "High"),
    ("test.php", "Test PHP Page", "Medium"),
    ("debug", "Debug Endpoint", "Medium"),
    (".git/HEAD", "Git Repository Exposure", "High"),
    (".env", "Environment File Exposure", "Critical"),
    ("backup.zip", "Backup Archive Exposure", "High"),
    ("backup.tar.gz", "Backup Archive Exposure", "High"),
    ("database.sql", "Database Dump Exposure", "Critical"),
]

SENSITIVE_MARKERS = ("password", "secret", "api_key", "apikey", "private_key", "access_key")
TECH_PATTERNS = [
    ("WordPress", re.compile(r"/wp-(?:content|includes)/|wordpress", re.I)),
    ("Drupal", re.compile(r"drupal-settings-json|/sites/default/", re.I)),
    ("Joomla", re.compile(r"joomla|/media/system/", re.I)),
    ("React", re.compile(r"react(?:\.production)?\.min\.js|__react", re.I)),
    ("Next.js", re.compile(r"/_next/|__next_f", re.I)),
    ("Vue.js", re.compile(r"vue(?:\.min)?\.js|data-v-[a-f0-9]", re.I)),
    ("Angular", re.compile(r"ng-version|angular(?:\.min)?\.js", re.I)),
]


def _issue(issue_type, severity, impact, fix, detail="", category="Web Checks"):
    item = {"type": issue_type, "severity": severity, "impact": impact, "fix": fix, "category": category}
    if detail:
        item["detail"] = detail
    return item


class WebSecurityScanner:
    def __init__(self, session: requests.Session, base_url: str, response, timeout=8, discover=True):
        self.session = session
        self.base_url = base_url
        self.response = response
        self.timeout = timeout
        self.discover = discover

    def scan(self):
        if not self.response:
            return []
        issues = []
        issues.extend(self._analyze_response())
        issues.extend(self._check_methods())
        issues.extend(self._check_cors())
        issues.extend(self._check_common_paths() if self.discover else [])
        issues.extend(self._fingerprint_technology())
        return issues

    def _analyze_response(self):
        issues = []
        h = {k.lower(): v for k, v in self.response.headers.items()}
        body = self.response.text[:500000]
        if self.response.url.startswith("http://") and self.base_url.startswith("https://"):
            issues.append(_issue("HTTPS Downgrade After Redirect", "Medium",
                "The requested HTTPS URL ended on HTTP, so transport protection was lost.",
                "Ensure redirects never downgrade HTTPS to HTTP.", f"Final URL: {self.response.url}", "Transport Security"))
        if "location" in h:
            loc = h["location"]
            if loc.startswith("http://") and self.base_url.startswith("https://"):
                issues.append(_issue("HTTP Redirect Location", "Medium",
                    "A redirect points from HTTPS to HTTP.",
                    "Change the redirect target to HTTPS.", f"Location: {loc}", "Transport Security"))
        ct = h.get("content-type", "")
        if "text/html" in ct and re.search(r"<!--.*?(password|api[_-]?key|secret|todo|debug).*?-->", body, re.I | re.S):
            issues.append(_issue("Sensitive Information in HTML Comments", "Low",
                "HTML comments appear to contain development or sensitive terms that are visible to clients.",
                "Remove secrets, credentials, internal notes and debug comments from production responses.", "Potential marker found in HTML comments."))
        if "index of /" in body.lower() and self.response.status_code == 200:
            issues.append(_issue("Directory Listing Enabled", "Medium",
                "The server appears to expose a browsable directory listing.",
                "Disable directory indexing/listing on the web server.", f"Detected on {self.response.url}"))
        if re.search(r"(stack trace|traceback \(|exception in thread|fatal error|undefined index:)", body, re.I):
            issues.append(_issue("Verbose Error Disclosure", "Medium",
                "The response appears to expose framework/runtime error details.",
                "Use generic production error pages and log detailed errors server-side only.", "Error/debug marker detected."))
        return issues

    def _check_methods(self):
        issues = []
        try:
            r = self.session.options(self.base_url, timeout=self.timeout, allow_redirects=False)
            allow = r.headers.get("Allow", "")
            if "TRACE" in allow.upper():
                issues.append(_issue("TRACE Method Enabled", "Medium",
                    "The TRACE method is advertised by the web server and can unnecessarily expand attack surface.",
                    "Disable TRACE unless it is explicitly required.", f"Allow: {allow}", "HTTP Methods"))
            if allow:
                dangerous = [m for m in ("PUT", "DELETE", "CONNECT") if m in allow.upper()]
                if dangerous:
                    issues.append(_issue("Potentially Risky HTTP Methods Enabled", "Low",
                        "The server advertises methods that can be dangerous when not required by the application.",
                        "Allow only HTTP methods required by the application and enforce authorization server-side.", f"Allow: {allow}; methods: {', '.join(dangerous)}", "HTTP Methods"))
        except requests.RequestException:
            pass
        return issues

    def _check_cors(self):
        issues = []
        try:
            r = self.session.get(self.base_url, headers={"Origin": "https://secprobe.invalid"}, timeout=self.timeout, allow_redirects=False)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == "*" and acac.lower() == "true":
                issues.append(_issue("Permissive CORS With Credentials", "High",
                    "The response allows every origin while also allowing credentials, which can expose authenticated data cross-origin in unsafe configurations.",
                    "Restrict Access-Control-Allow-Origin to an explicit trusted origin list and avoid credentials with wildcard origins.",
                    f"ACAO: {acao}; ACAC: {acac}", "CORS"))
            elif acao == "*":
                issues.append(_issue("Wildcard CORS Policy", "Low",
                    "The endpoint permits cross-origin requests from any origin.",
                    "Use an explicit origin allowlist for endpoints that return sensitive data.", "Access-Control-Allow-Origin: *", "CORS"))
            elif acao == "https://secprobe.invalid":
                issues.append(_issue("Origin Reflected in CORS", "Medium",
                    "The server reflected an arbitrary Origin value in Access-Control-Allow-Origin.",
                    "Validate Origin against a strict allowlist instead of reflecting it blindly.", f"ACAO: {acao}", "CORS"))
        except requests.RequestException:
            pass
        return issues

    def _check_common_paths(self):
        issues = []
        seen = set()

        # Soft-404 baseline: request a path that (almost certainly) doesn't
        # exist first. Many sites (SPAs, WordPress catch-alls, custom error
        # pages) return HTTP 200 for *any* path instead of a real 404, which
        # would otherwise make every check below fire as a false positive.
        # If a real path's response matches this baseline closely enough,
        # we treat it as "not actually there" and skip it.
        probe_path = "secprobe-nonexistent-check-8f3a1c2e/"
        baseline = None
        try:
            probe_url = urljoin(self.base_url.rstrip('/') + '/', probe_path)
            br = self.session.get(probe_url, timeout=self.timeout, allow_redirects=False)
            if br.status_code in (200, 206):
                baseline = {
                    "status_code": br.status_code,
                    "length": len(br.text),
                    "text": br.text[:20000],
                }
        except requests.RequestException:
            pass

        def looks_like_baseline(r):
            if baseline is None:
                return False
            if r.status_code != baseline["status_code"]:
                return False
            # Same status and near-identical body length/content -> soft-404 page.
            body = r.text[:20000]
            if body == baseline["text"]:
                return True
            len_a, len_b = len(body), baseline["length"]
            if len_b == 0:
                return len_a == 0
            similarity = 1 - (abs(len_a - len_b) / max(len_a, len_b, 1))
            return similarity > 0.95

        for path, label, severity in COMMON_PATHS:
            url = urljoin(self.base_url.rstrip('/') + '/', path)
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            except requests.RequestException:
                continue
            if r.status_code not in (200, 206):
                continue
            if looks_like_baseline(r):
                continue
            ctype = r.headers.get("Content-Type", "").lower()
            body = r.text[:20000]
            key = (label, url)
            if key in seen:
                continue
            seen.add(key)
            if path in ("robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt"):
                issues.append(_issue(f"Exposed {label}", "Info",
                    f"A standard public resource is available at {url}.",
                    "Review the content to ensure it does not disclose internal paths or sensitive information.", f"HTTP {r.status_code}; Content-Type: {ctype or 'unknown'}", "Resource Discovery"))
            elif path == ".git/HEAD":
                issues.append(_issue("Git Repository Exposed", "High",
                    "A Git metadata endpoint is publicly accessible and may expose repository history and source information.",
                    "Remove .git from the web root and block access to VCS metadata.", f"HTTP {r.status_code}; body: {body[:100]}", "Sensitive Files"))
            elif path == ".env":
                issues.append(_issue("Environment File Exposed", "Critical",
                    "An environment configuration file is publicly accessible and may contain credentials or secrets.",
                    "Remove .env from the web root and block access to hidden/configuration files.", f"HTTP {r.status_code}; sensitive marker: {any(x in body.lower() for x in SENSITIVE_MARKERS)}", "Sensitive Files"))
            elif path in ("database.sql", "backup.zip", "backup.tar.gz"):
                issues.append(_issue(f"Potential Backup/Data File Exposed: {path}", severity,
                    "A commonly named backup or database file is directly accessible.",
                    "Remove backups from the web root and store them outside publicly served directories.", f"HTTP {r.status_code}; Content-Type: {ctype}", "Sensitive Files"))
            else:
                issues.append(_issue(f"Potentially Sensitive Endpoint: {path}", severity,
                    f"A commonly exposed diagnostic or administrative resource responded with HTTP {r.status_code}.",
                    "Remove or restrict diagnostic/admin endpoints in production.", f"URL: {url}; Content-Type: {ctype}", "Sensitive Files"))
        return issues

    def _fingerprint_technology(self):
        issues = []
        text = self.response.text[:500000]
        found = []
        for name, pattern in TECH_PATTERNS:
            if pattern.search(text):
                found.append(name)
        server = self.response.headers.get("Server")
        powered = self.response.headers.get("X-Powered-By")
        if found or server or powered:
            detail = []
            if found: detail.append("content=" + ", ".join(found))
            if server: detail.append("Server=" + server)
            if powered: detail.append("X-Powered-By=" + powered)
            issues.append(_issue("Technology Fingerprint", "Info",
                "Public responses reveal technology indicators that can help defenders understand the deployed stack and attackers target it.",
                "Minimize unnecessary technology/version disclosure while keeping required functionality intact.", "; ".join(detail), "Fingerprinting"))
        return issues
