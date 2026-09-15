"""SecProbe core scanner engine.

Nikto-inspired, non-exploitative web reconnaissance and configuration auditing.
"""
import time
import requests
import urllib3
from typing import Optional
from .modules.headers import HeaderScanner
from .modules.ssl_checker import SSLChecker
from .modules.port_scanner import PortScanner
from .modules.version_fingerprint import VersionFingerprinter
from .modules.web_checks import WebSecurityScanner
from .modules.ai_explainer import AIExplainer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0}


class SecProbe:
    def __init__(self, target: str, scan_ports=False, use_ai=True,
                 gemini_key: Optional[str]=None, groq_key: Optional[str]=None,
                 check_cve=False, nvd_api_key: Optional[str]=None,
                 discover=True, timeout=10):
        # True when the caller typed http:// or https:// themselves; in that
        # case we respect it exactly and never silently fall back to the
        # other scheme (useful for verifying "does this host reject plain
        # HTTP", for example).
        self._explicit_scheme = target.strip().lower().startswith(("http://", "https://"))
        self.target = self._normalize_target(target)
        self.scan_ports = scan_ports
        self.use_ai = use_ai
        self.gemini_key = gemini_key
        self.groq_key = groq_key
        self.check_cve = check_cve
        self.nvd_api_key = nvd_api_key
        self.discover = discover
        self.timeout = timeout
        self.issues = []
        self.score = 100
        self.scan_time = 0
        self.debug_info = {}

    def _normalize_target(self, target):
        target = target.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target.rstrip("/")

    def _candidate_urls(self):
        primary = self.target
        if self._explicit_scheme:
            return [primary]
        if primary.startswith("https://"):
            return [primary, "http://" + primary[len("https://"):]]
        return [primary, "https://" + primary[len("http://"):]]

    def _fetch_response(self, session):
        """
        Try the target's own scheme first, then fall back to the opposite
        scheme on connection failure. Returns (response, resolved_scheme, errors)
        so the caller knows *for certain* which scheme actually produced the
        response — self.target's original scheme is not trustworthy on its own,
        since a https:// attempt may have silently fallen back to http://.
        """
        errors = []
        for url in self._candidate_urls():
            try:
                r = session.get(url, timeout=self.timeout, allow_redirects=True, verify=False,
                                 headers={"Cache-Control": "no-cache", "Pragma": "no-cache",
                                          "User-Agent": "SecProbe/1.0 (authorized-security-audit)"})
                resolved_scheme = "https" if url.startswith("https://") else "http"
                return r, resolved_scheme, errors
            except requests.RequestException as exc:
                errors.append(f"{url}: {exc}")
        return None, None, errors

    def run(self):
        start = time.time()
        session = requests.Session()
        session.headers.update({"User-Agent": "SecProbe/1.0 (authorized-security-audit)"})
        response, resolved_scheme, errors = self._fetch_response(session)
        from urllib.parse import urlparse
        hostname = urlparse(self.target).hostname

        # Reflect what we actually connected with, not just what the caller typed.
        used_https = resolved_scheme == "https"
        if response is not None and resolved_scheme is not None:
            self.target = resolved_scheme + "://" + self.target.split("://", 1)[1]

        self.debug_info = {
            "requested_target": self.target,
            "resolved_hostname": hostname,
            "final_url_after_redirects": response.url if response else None,
            "status_code": response.status_code if response else None,
            "content_length": len(response.content) if response else 0,
            "raw_headers": dict(response.headers) if response else {},
            "used_https": used_https,
            "redirect_chain": [r.url for r in response.history] if response else [],
            "connection_attempts": errors,
        }
        issues = []
        issues.extend(HeaderScanner(response).scan())
        # Only perform TLS analysis when the scan actually connected over HTTPS.
        # Using the resolved scheme (not the originally-requested one) avoids
        # running port-443 checks against a host that just proved it only
        # answers over plain HTTP.
        if used_https:
            issues.extend(SSLChecker(hostname).scan())
        elif response is not None:
            issues.append({"type": "HTTPS Not Available", "severity": "High",
                           "impact": "This scan reached the target over plain HTTP only; traffic is unencrypted and SSL/TLS was not evaluated.",
                           "fix": "Enable HTTPS with a valid certificate and redirect all HTTP traffic to HTTPS.",
                           "category": "Transport Security"})
        if response:
            issues.extend(WebSecurityScanner(session, self.target, response, timeout=min(self.timeout, 8), discover=self.discover).scan())
        if self.scan_ports:
            issues.extend(PortScanner(hostname).scan())
        if self.check_cve:
            issues.extend(VersionFingerprinter(response, nvd_api_key=self.nvd_api_key).scan())
        if self.use_ai and issues:
            issues = AIExplainer(gemini_key=self.gemini_key, groq_key=self.groq_key).enrich(issues)
        self.issues = self._deduplicate(issues)
        self.score = self._compute_score(self.issues)
        self.scan_time = round(time.time() - start, 2)
        return self._build_report()

    @staticmethod
    def _deduplicate(issues):
        out, seen = [], set()
        for issue in issues:
            key = (issue.get("type"), issue.get("detail", ""))
            if key not in seen:
                seen.add(key); out.append(issue)
        return out

    def _compute_score(self, issues):
        return max(0, 100 - sum(SEVERITY_WEIGHTS.get(i.get("severity", "Info"), 0) for i in issues))

    def _build_report(self):
        return {
            "target": self.target, "score": self.score, "grade": self._grade(self.score),
            "scan_time_seconds": self.scan_time, "total_issues": len(self.issues),
            "issues": self.issues, "debug": self.debug_info,
            "scan_profile": {"nikto_like": True, "active_exploit_testing": False,
                             "common_resource_discovery": self.discover, "ports": self.scan_ports,
                             "cve_banner_matching": self.check_cve},
            "summary": {k.lower(): sum(1 for i in self.issues if i.get("severity") == k)
                        for k in ("Critical", "High", "Medium", "Low", "Info")},
        }

    @staticmethod
    def _grade(score):
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"
