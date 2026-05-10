"""
SecProbe - HTTP Security Headers Scanner Module
Checks for missing or misconfigured security headers.
"""

from typing import Optional


SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "impact": "Allows cross-site scripting (XSS) attacks and data injection.",
        "fix": "Add a Content-Security-Policy header restricting allowed sources.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    },
    "Strict-Transport-Security": {
        "severity": "High",
        "impact": "Without HSTS, browsers may connect over HTTP, enabling MITM attacks.",
        "fix": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "impact": "Site may be embedded in iframes, enabling clickjacking attacks.",
        "fix": "Add: X-Frame-Options: DENY or SAMEORIGIN",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "impact": "Browsers may MIME-sniff responses, leading to XSS vulnerabilities.",
        "fix": "Add: X-Content-Type-Options: nosniff",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "Referrer-Policy": {
        "severity": "Low",
        "impact": "Full URL may leak in the Referer header to third-party sites.",
        "fix": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": "Low",
        "impact": "Browser features (camera, mic, geolocation) may be accessed by scripts.",
        "fix": "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "impact": "Some older browsers lack built-in XSS filtering.",
        "fix": "Add: X-XSS-Protection: 1; mode=block (legacy support)",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    },
}

INSECURE_HEADER_CHECKS = {
    "Server": {
        "severity": "Info",
        "impact": "Server version disclosure can aid attackers in fingerprinting.",
        "fix": "Remove or sanitize the Server header to hide version info.",
    },
    "X-Powered-By": {
        "severity": "Info",
        "impact": "Technology stack disclosure can help attackers choose targeted exploits.",
        "fix": "Remove the X-Powered-By header from server responses.",
    },
}


class HeaderScanner:
    def __init__(self, response):
        self.response = response
        self.headers = response.headers if response else {}

    def scan(self) -> list:
        issues = []

        if not self.response:
            issues.append({
                "type": "Connection Failed",
                "severity": "Critical",
                "impact": "Could not connect to the target. The host may be down or blocking requests.",
                "fix": "Verify the target URL is correct and accessible.",
                "category": "Connectivity",
            })
            return issues

        
        for header, meta in SECURITY_HEADERS.items():
            if header.lower() not in {k.lower() for k in self.headers}:
                issues.append({
                    "type": f"Missing {header}",
                    "severity": meta["severity"],
                    "impact": meta["impact"],
                    "fix": meta["fix"],
                    "reference": meta["reference"],
                    "category": "HTTP Headers",
                })

        
        for header, meta in INSECURE_HEADER_CHECKS.items():
            value = self.headers.get(header)
            if value:
                issues.append({
                    "type": f"Header Disclosure: {header}",
                    "severity": meta["severity"],
                    "impact": meta["impact"],
                    "fix": meta["fix"],
                    "category": "Information Disclosure",
                    "detail": f"Value: {value}",
                })

        
        set_cookie = self.headers.get("Set-Cookie", "")
        if set_cookie:
            cookie_issues = self._check_cookie(set_cookie)
            issues.extend(cookie_issues)

        return issues

    def _check_cookie(self, cookie_str: str) -> list:
        issues = []
        cookie_lower = cookie_str.lower()

        if "secure" not in cookie_lower:
            issues.append({
                "type": "Cookie Missing Secure Flag",
                "severity": "High",
                "impact": "Cookie can be transmitted over unencrypted HTTP connections.",
                "fix": "Set the Secure flag on all cookies: Set-Cookie: name=value; Secure",
                "category": "Cookie Security",
            })

        if "httponly" not in cookie_lower:
            issues.append({
                "type": "Cookie Missing HttpOnly Flag",
                "severity": "Medium",
                "impact": "Cookies accessible via JavaScript; vulnerable to XSS theft.",
                "fix": "Set the HttpOnly flag: Set-Cookie: name=value; HttpOnly",
                "category": "Cookie Security",
            })

        if "samesite" not in cookie_lower:
            issues.append({
                "type": "Cookie Missing SameSite Attribute",
                "severity": "Medium",
                "impact": "Cookies sent with cross-site requests, enabling CSRF attacks.",
                "fix": "Add SameSite=Strict or SameSite=Lax to your cookies.",
                "category": "Cookie Security",
            })

        return issues
