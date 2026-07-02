"""
SecProbe - Version Fingerprinting & Known-CVE Matching Module
Passively identifies software/version banners from response headers and
cross-references them against the official NVD (National Vulnerability
Database) API — the same free, public source Nessus/OpenVAS-style tools
build their signature feeds from.

IMPORTANT — read before trusting the output:
  - Detection is BANNER-BASED ONLY. It reads what the server volunteers in
    headers like `Server` and `X-Powered-By`. It does not probe the app,
    fingerprint via behavior, or verify the version any other way.
  - Banners are frequently wrong: many admins deliberately strip or fake
    them, reverse proxies/CDNs often rewrite them, and a banner can be
    stale if a package was upgraded without changing its advertised string.
  - This means both false positives (flagging a CVE that doesn't actually
    apply) and false negatives (missing a real, unadvertised version) are
    expected. Treat every finding here as "worth manually verifying",
    not as confirmed.
  - This module only reads public CVE records and never sends exploit
    payloads or attempts to trigger/verify any vulnerability.

Author: Aman Kumar Panda
"""

import re
import time
import requests
from typing import Optional

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Without an API key, NVD enforces 5 requests / rolling 30s.
# With a free key (https://nvd.nist.gov/developers/request-an-api-key), it's 50 / 30s.
NO_KEY_DELAY_SECONDS = 6
WITH_KEY_DELAY_SECONDS = 0.6

# product -> a cleaner NVD keyword search term
PRODUCT_ALIASES = {
    "nginx": "nginx",
    "apache": "apache http server",
    "microsoft-iis": "microsoft iis",
    "iis": "microsoft iis",
    "php": "php",
    "openssl": "openssl",
    "express": "express.js node",
    "node": "node.js",
    "gunicorn": "gunicorn",
    "werkzeug": "werkzeug",
    "tomcat": "apache tomcat",
    "jetty": "eclipse jetty",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "django": "django",
    "rails": "ruby on rails",
    "openssh": "openssh",
    "varnish": "varnish cache",
    "cloudflare": None,  # CDN edge banner, not a fingerprintable origin version
}

# Server/X-Powered-By style "Product/Version" tokens, e.g. "nginx/1.18.0",
# "Apache/2.4.41 (Ubuntu)", "PHP/7.4.3", "Microsoft-IIS/10.0"
VERSION_TOKEN_RE = re.compile(r"([A-Za-z][A-Za-z0-9\-\.]*)\/(\d+(?:\.\d+){1,3})")

CVSS_TO_SEVERITY = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
]

MAX_CVES_PER_PRODUCT = 5


def _cvss_severity(score: Optional[float]) -> str:
    if score is None:
        return "Info"
    for threshold, sev in CVSS_TO_SEVERITY:
        if score >= threshold:
            return sev
    return "Info"


class VersionFingerprinter:
    def __init__(self, response, nvd_api_key: Optional[str] = None, timeout: int = 15):
        self.response = response
        self.headers = response.headers if response else {}
        self.nvd_api_key = nvd_api_key
        self.timeout = timeout
        self.delay = WITH_KEY_DELAY_SECONDS if nvd_api_key else NO_KEY_DELAY_SECONDS

    def scan(self) -> list:
        if not self.response:
            return []

        detections = self._detect_versions()
        if not detections:
            return []

        issues = []
        for i, (product, version, source_header) in enumerate(detections):
            # Always surface the raw detection itself, even if the CVE
            # lookup fails or the network is unavailable — that's still
            # useful "you're leaking a version banner" information.
            issues.append({
                "type": f"Version Disclosure: {product} {version}",
                "severity": "Info",
                "impact": f"The {source_header} header advertises {product} {version}, "
                          f"giving attackers a starting point for targeted research.",
                "fix": f"Suppress or genericize the {source_header} header at the server/proxy level.",
                "category": "Version Fingerprinting",
                "detail": f"Detected via {source_header} header. Banner-based — verify manually before acting.",
            })

            cve_issues = self._lookup_cves(product, version)
            issues.extend(cve_issues)

            # Respect NVD rate limits between lookups, not before the first one
            if i < len(detections) - 1:
                time.sleep(self.delay)

        return issues

    def _detect_versions(self) -> list:
        found = []
        seen = set()
        for header_name in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
            value = self.headers.get(header_name)
            if not value:
                continue
            for match in VERSION_TOKEN_RE.finditer(value):
                raw_product, version = match.group(1), match.group(2)
                key = (raw_product.lower(), version)
                if key in seen:
                    continue
                seen.add(key)
                found.append((raw_product, version, header_name))
        return found

    def _lookup_cves(self, raw_product: str, version: str) -> list:
        alias_key = raw_product.lower()
        search_term = PRODUCT_ALIASES.get(alias_key, raw_product)
        if search_term is None:
            return []  # known non-origin banner (e.g. a CDN), skip lookup

        query = f"{search_term} {version}"
        try:
            resp = requests.get(
                NVD_API_URL,
                params={"keywordSearch": query, "resultsPerPage": 20},
                headers={"apiKey": self.nvd_api_key} if self.nvd_api_key else {},
                timeout=self.timeout,
            )
            if resp.status_code == 403:
                return [self._lookup_failed_issue(
                    raw_product, version,
                    "NVD rate-limited this request (403). Get a free API key at "
                    "https://nvd.nist.gov/developers/request-an-api-key for higher limits."
                )]
            if resp.status_code != 200:
                return [self._lookup_failed_issue(
                    raw_product, version, f"NVD API returned HTTP {resp.status_code}."
                )]
            data = resp.json()
        except requests.exceptions.RequestException as e:
            return [self._lookup_failed_issue(raw_product, version, str(e))]
        except ValueError:
            return [self._lookup_failed_issue(raw_product, version, "NVD returned an unparseable response.")]

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return []

        # Only keep entries whose description actually mentions this version
        # string, to cut down on keyword-search noise (NVD keywordSearch is
        # a broad text match, not a precise CPE match).
        relevant = []
        for v in vulns:
            cve = v.get("cve", {})
            descriptions = cve.get("descriptions", [])
            desc_text = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            if version in desc_text or version in cve.get("id", ""):
                relevant.append((cve, desc_text))

        # Fall back to the raw result set if the stricter version-text
        # filter eliminated everything — better to show possibly-loose
        # matches (clearly labeled) than silently show nothing.
        candidates = relevant if relevant else [
            (v.get("cve", {}), next((d.get("value", "") for d in v.get("cve", {}).get("descriptions", []) if d.get("lang") == "en"), ""))
            for v in vulns
        ]
        loosely_matched = not relevant

        issues = []
        # Sort by CVSS score (highest first) so the most severe surfaces first
        def score_of(item):
            cve, _ = item
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    return metrics[key][0].get("cvssData", {}).get("baseScore", 0)
            return 0

        candidates.sort(key=score_of, reverse=True)

        for cve, desc_text in candidates[:MAX_CVES_PER_PRODUCT]:
            cve_id = cve.get("id", "Unknown CVE")
            score = score_of((cve, desc_text)) or None
            severity = _cvss_severity(score)
            short_desc = (desc_text[:220] + "…") if len(desc_text) > 220 else desc_text
            match_note = " (loosely matched by keyword — version not confirmed in the advisory text)" if loosely_matched else ""

            issues.append({
                "type": f"Possible Known Vulnerability: {cve_id} in {raw_product} {version}",
                "severity": severity,
                "impact": short_desc or "See the NVD reference for full details.",
                "fix": f"Verify whether {raw_product} {version} is actually affected, and if so, "
                       f"upgrade to a patched release per the vendor's advisory.",
                "category": "Known Vulnerabilities (CVE)",
                "detail": f"CVSS: {score if score is not None else 'N/A'}{match_note}",
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        return issues

    @staticmethod
    def _lookup_failed_issue(product: str, version: str, reason: str) -> dict:
        return {
            "type": f"CVE Lookup Failed: {product} {version}",
            "severity": "Info",
            "impact": "Could not check the NVD database for known vulnerabilities in this detected version.",
            "fix": "Retry the scan, or manually check https://nvd.nist.gov for this product/version.",
            "category": "Known Vulnerabilities (CVE)",
            "detail": reason,
        }
