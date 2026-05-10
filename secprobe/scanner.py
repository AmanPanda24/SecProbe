"""
SecProbe Core Scanner Engine
Orchestrates all scanning modules and computes the security score.
Author: Aman Kumar Panda
"""

import requests
import time
from typing import Optional
from .modules.headers import HeaderScanner
from .modules.ssl_checker import SSLChecker
from .modules.port_scanner import PortScanner
from .modules.ai_explainer import AIExplainer

SEVERITY_WEIGHTS = {
    "Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 0,
}


class SecProbe:
    def __init__(
        self,
        target: str,
        scan_ports: bool = False,
        use_ai: bool = True,
        gemini_key: Optional[str] = None,
        groq_key: Optional[str] = None,
    ):
        self.target = self._normalize_target(target)
        self.scan_ports = scan_ports
        self.use_ai = use_ai
        self.gemini_key = gemini_key
        self.groq_key = groq_key
        self.issues = []
        self.score = 100
        self.scan_time = 0

    def _normalize_target(self, target: str) -> str:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target.rstrip("/")

    def _get_hostname(self) -> str:
        from urllib.parse import urlparse
        return urlparse(self.target).hostname

    def _fetch_response(self):
        try:
            return requests.get(self.target, timeout=10, allow_redirects=True, verify=False)
        except requests.exceptions.SSLError:
            try:
                return requests.get(self.target, timeout=10, verify=False, allow_redirects=True)
            except Exception:
                return None
        except Exception:
            return None

    def run(self) -> dict:
        start = time.time()
        response = self._fetch_response()
        hostname = self._get_hostname()
        all_issues = []

        all_issues.extend(HeaderScanner(response).scan())
        all_issues.extend(SSLChecker(hostname).scan())

        if self.scan_ports:
            all_issues.extend(PortScanner(hostname).scan())

        if self.use_ai:
            explainer = AIExplainer(
                gemini_key=self.gemini_key,
                groq_key=self.groq_key,
            )
            all_issues = explainer.enrich(all_issues)

        self.issues = all_issues
        self.score = self._compute_score(all_issues)
        self.scan_time = round(time.time() - start, 2)
        return self._build_report()

    def _compute_score(self, issues: list) -> int:
        deduction = sum(SEVERITY_WEIGHTS.get(i.get("severity", "Info"), 0) for i in issues)
        return max(0, 100 - deduction)

    def _build_report(self) -> dict:
        return {
            "target": self.target,
            "score": self.score,
            "grade": self._grade(self.score),
            "scan_time_seconds": self.scan_time,
            "total_issues": len(self.issues),
            "issues": self.issues,
            "summary": {
                "critical": sum(1 for i in self.issues if i.get("severity") == "Critical"),
                "high":     sum(1 for i in self.issues if i.get("severity") == "High"),
                "medium":   sum(1 for i in self.issues if i.get("severity") == "Medium"),
                "low":      sum(1 for i in self.issues if i.get("severity") == "Low"),
                "info":     sum(1 for i in self.issues if i.get("severity") == "Info"),
            },
        }

    @staticmethod
    def _grade(score: int) -> str:
        if score >= 90: return "A"
        if score >= 75: return "B"
        if score >= 60: return "C"
        if score >= 40: return "D"
        return "F"
