"""
SecProbe - Unit Tests
Run: python -m pytest tests/ -v
"""

import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secprobe.scanner import SecProbe
from secprobe.modules.headers import HeaderScanner
from secprobe.modules.version_fingerprint import VersionFingerprinter
from secprobe.modules.ai_explainer import AIExplainer, OfflineExplainer
from unittest.mock import patch, MagicMock


class MockResponse:
    def __init__(self, headers=None, status_code=200):
        self.headers = headers or {}
        self.status_code = status_code

class TestHeaderScanner:
    def test_missing_all_headers(self):
        issues = HeaderScanner(MockResponse()).scan()
        types = [i["type"] for i in issues]
        assert "Missing Content-Security-Policy" in types
        assert "Missing Strict-Transport-Security" in types
        assert "Missing X-Frame-Options" in types

    def test_all_headers_present(self):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
            "X-XSS-Protection": "1; mode=block",
        }
        issues = HeaderScanner(MockResponse(headers=headers)).scan()
        assert not [i for i in issues if i["category"] == "HTTP Headers"]

    def test_server_disclosure(self):
        issues = HeaderScanner(MockResponse(headers={"Server": "Apache/2.4.51"})).scan()
        assert any("Server" in i["type"] and "Disclosure" in i["type"] for i in issues)

    def test_cookie_missing_all_flags(self):
        issues = HeaderScanner(MockResponse(headers={"Set-Cookie": "sess=abc; Path=/"})).scan()
        cookie = [i for i in issues if i["category"] == "Cookie Security"]
        assert len(cookie) == 3

    def test_cookie_all_flags_set(self):
        issues = HeaderScanner(MockResponse(headers={
            "Set-Cookie": "sess=abc; Secure; HttpOnly; SameSite=Strict"
        })).scan()
        assert not [i for i in issues if i["category"] == "Cookie Security"]

    def test_no_response(self):
        issues = HeaderScanner(None).scan()
        assert issues[0]["severity"] == "Critical"

class TestScoring:
    def _probe(self):
        return SecProbe.__new__(SecProbe)

    def test_perfect(self):
        assert self._probe()._compute_score([]) == 100

    def test_high_deduction(self):
        assert self._probe()._compute_score([{"severity": "High"}]) == 85

    def test_critical_deduction(self):
        assert self._probe()._compute_score([{"severity": "Critical"}]) == 75

    def test_floor_zero(self):
        assert self._probe()._compute_score([{"severity": "Critical"}] * 10) == 0

    def test_grades(self):
        assert SecProbe._grade(95) == "A"
        assert SecProbe._grade(80) == "B"
        assert SecProbe._grade(65) == "C"
        assert SecProbe._grade(50) == "D"
        assert SecProbe._grade(20) == "F"

class TestVersionFingerprinter:
    def _mock_nvd(self, cve_id, description, cvss_score, status_code=200):
        def fake_get(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            resp.status_code = status_code
            resp.json.return_value = {
                "vulnerabilities": [{
                    "cve": {
                        "id": cve_id,
                        "descriptions": [{"lang": "en", "value": description}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss_score}}]},
                    }
                }]
            }
            return resp
        return fake_get

    def test_detects_version_from_server_header(self):
        resp = MockResponse(headers={"Server": "nginx/1.18.0 (Ubuntu)"})
        with patch("secprobe.modules.version_fingerprint.requests.get",
                   side_effect=self._mock_nvd("CVE-2021-23017", "issue in nginx 1.18.0", 9.4)), \
             patch("secprobe.modules.version_fingerprint.time.sleep", return_value=None):
            issues = VersionFingerprinter(resp).scan()
        types = [i["type"] for i in issues]
        assert any("Version Disclosure: nginx 1.18.0" in t for t in types)

    def test_matches_cve_mentioning_exact_version(self):
        resp = MockResponse(headers={"Server": "nginx/1.18.0"})
        with patch("secprobe.modules.version_fingerprint.requests.get",
                   side_effect=self._mock_nvd("CVE-2021-23017", "A flaw in nginx 1.18.0 resolver.", 9.4)), \
             patch("secprobe.modules.version_fingerprint.time.sleep", return_value=None):
            issues = VersionFingerprinter(resp).scan()
        cve_issues = [i for i in issues if i["category"] == "Known Vulnerabilities (CVE)"]
        assert len(cve_issues) == 1
        assert cve_issues[0]["severity"] == "Critical"
        assert "loosely matched" not in cve_issues[0]["detail"]

    def test_falls_back_to_loose_match_when_version_not_in_text(self):
        resp = MockResponse(headers={"Server": "nginx/1.18.0"})
        with patch("secprobe.modules.version_fingerprint.requests.get",
                   side_effect=self._mock_nvd("CVE-9999-0001", "An unrelated generic nginx issue.", 5.0)), \
             patch("secprobe.modules.version_fingerprint.time.sleep", return_value=None):
            issues = VersionFingerprinter(resp).scan()
        cve_issues = [i for i in issues if i["category"] == "Known Vulnerabilities (CVE)"]
        assert len(cve_issues) == 1
        assert "loosely matched" in cve_issues[0]["detail"]

    def test_handles_nvd_rate_limit_gracefully(self):
        resp = MockResponse(headers={"Server": "nginx/1.18.0"})
        with patch("secprobe.modules.version_fingerprint.requests.get",
                   side_effect=self._mock_nvd("x", "x", 0, status_code=403)), \
             patch("secprobe.modules.version_fingerprint.time.sleep", return_value=None):
            issues = VersionFingerprinter(resp).scan()
        assert any("CVE Lookup Failed" in i["type"] for i in issues)

    def test_no_response_returns_no_issues(self):
        assert VersionFingerprinter(None).scan() == []

    def test_no_version_headers_returns_no_lookup(self):
        resp = MockResponse(headers={"Content-Type": "text/html"})
        with patch("secprobe.modules.version_fingerprint.requests.get") as mock_get:
            issues = VersionFingerprinter(resp).scan()
        mock_get.assert_not_called()
        assert issues == []

    def test_cdn_banner_skips_cve_lookup(self):
        resp = MockResponse(headers={"Server": "cloudflare/1.0"})
        with patch("secprobe.modules.version_fingerprint.requests.get") as mock_get:
            issues = VersionFingerprinter(resp).scan()
        mock_get.assert_not_called()
        assert any("Version Disclosure" in i["type"] for i in issues)


class TestOfflineExplainer:
    def test_enriches_all_issues(self):
        issues = [
            {"type": "Missing Content-Security-Policy", "severity": "High"},
            {"type": "Cookie Missing Secure Flag", "severity": "High"},
        ]
        enriched = OfflineExplainer().enrich(issues)
        assert len(enriched) == 2
        for e in enriched:
            assert "ai_impact" in e
            assert "ai_fix" in e
            assert "risk_score" in e
            assert e["ai_provider"] == "offline"

    def test_risk_score_for_critical(self):
        enriched = OfflineExplainer().enrich([{"type": "x", "severity": "Critical"}])
        assert enriched[0]["risk_score"] == 9.5

    def test_empty_list(self):
        explainer = AIExplainer()
        assert explainer.enrich([]) == []

    def test_fallback_to_offline_no_keys(self):
        explainer = AIExplainer(gemini_key=None, groq_key=None)
        issues = [{"type": "Missing X-Frame-Options", "severity": "Medium"}]
        result = explainer.enrich(issues)
        assert result[0].get("ai_provider") == "offline"

class TestAPI:
    @pytest.fixture
    def client(self):
        from secprobe.api import app
        app.config["TESTING"] = True
        with app.test_client() as c:
            yield c

    def test_index(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["name"] == "SecProbe API"
        assert "ai_providers" in data

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "ai_provider" in data

    def test_scan_missing_target(self, client):
        resp = client.post("/scan", json={})
        assert resp.status_code == 400

    def test_docs(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200
        assert "POST /scan" in resp.get_json()

    def test_404(self, client):
        assert client.get("/nonexistent").status_code == 404

    def test_method_not_allowed(self, client):
        assert client.get("/scan").status_code == 405


class FakeResponse:
    def __init__(self, url="https://example.test", status_code=200, headers=None, text="<html>ok</html>"):
        self.url = url
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.text = text
        self.content = text.encode()


class FakeSession:
    """Routes session.get()/options() calls to a caller-supplied handler
    so each test can script exactly what the 'server' returns per path."""
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def get(self, url, timeout=None, allow_redirects=None, headers=None):
        self.calls.append(("GET", url, headers))
        return self.handler(url, headers)

    def options(self, url, timeout=None, allow_redirects=None):
        self.calls.append(("OPTIONS", url, None))
        r = self.handler(url, {"__method__": "OPTIONS"})
        return r


class TestWebSecurityScanner:
    from secprobe.modules.web_checks import WebSecurityScanner as _WSS

    def _not_found(self, url, headers=None):
        # Real 404 for anything not explicitly handled by a test.
        return FakeResponse(url=url, status_code=404, headers={"Content-Type": "text/html"}, text="not found")

    def test_soft_404_suppresses_false_positives(self):
        # Every path, including the baseline probe, returns 200 with the
        # same generic body -> nothing should be reported as "exposed".
        soft_body = "<html><body>Page not found, sorry!</body></html>"

        def handler(url, headers):
            return FakeResponse(url=url, status_code=200,
                                 headers={"Content-Type": "text/html"}, text=soft_body)

        session = FakeSession(handler)
        base = FakeResponse(url="https://spa.example.test", text="<html>home</html>")
        issues = self._WSS(session, "https://spa.example.test", base, discover=True).scan()
        sensitive = [i for i in issues if i["category"] in ("Sensitive Files",)]
        assert sensitive == []

    def test_real_env_exposure_still_detected_despite_soft_404_site(self):
        soft_body = "<html><body>Page not found, sorry!</body></html>"

        def handler(url, headers):
            if url.endswith(".env"):
                return FakeResponse(url=url, status_code=200,
                                     headers={"Content-Type": "text/plain"},
                                     text="DB_PASSWORD=hunter2\nAPI_KEY=abcd1234")
            return FakeResponse(url=url, status_code=200,
                                 headers={"Content-Type": "text/html"}, text=soft_body)

        session = FakeSession(handler)
        base = FakeResponse(url="https://spa.example.test", text="<html>home</html>")
        issues = self._WSS(session, "https://spa.example.test", base, discover=True).scan()
        types = [i["type"] for i in issues]
        assert "Environment File Exposed" in types

    def test_real_404_site_env_not_flagged(self):
        def handler(url, headers):
            if url.endswith(".env"):
                return FakeResponse(url=url, status_code=404, text="not found")
            return self._not_found(url, headers)

        session = FakeSession(handler)
        base = FakeResponse(url="https://normal.example.test", text="<html>home</html>")
        issues = self._WSS(session, "https://normal.example.test", base, discover=True).scan()
        assert issues == [] or all(i["category"] != "Sensitive Files" for i in issues)

    def test_discover_false_skips_path_checks(self):
        calls = []

        def handler(url, headers):
            calls.append(url)
            return self._not_found(url, headers)

        session = FakeSession(handler)
        base = FakeResponse(url="https://example.test", text="<html>home</html>")
        self._WSS(session, "https://example.test", base, discover=False).scan()
        assert not any(".env" in u or "backup" in u for u in calls)

    def test_trace_method_flagged(self):
        def handler(url, headers):
            r = FakeResponse(url=url, status_code=200, text="")
            r.headers = {"Allow": "GET, POST, TRACE"}
            return r

        session = FakeSession(handler)
        base = FakeResponse(url="https://example.test", text="<html></html>")
        issues = self._WSS(session, "https://example.test", base, discover=False).scan()
        assert any(i["type"] == "TRACE Method Enabled" for i in issues)

    def test_permissive_cors_with_credentials_flagged(self):
        def handler(url, headers):
            if headers and headers.get("Origin"):
                r = FakeResponse(url=url, status_code=200, text="")
                r.headers = {"Access-Control-Allow-Origin": "*",
                             "Access-Control-Allow-Credentials": "true"}
                return r
            return FakeResponse(url=url, status_code=200, headers={"Allow": ""}, text="")

        session = FakeSession(handler)
        base = FakeResponse(url="https://example.test", text="<html></html>")
        issues = self._WSS(session, "https://example.test", base, discover=False).scan()
        assert any(i["type"] == "Permissive CORS With Credentials" for i in issues)

    def test_directory_listing_detected(self):
        base = FakeResponse(url="https://example.test", status_code=200,
                             text="<html><title>Index of /uploads</title></html>")
        session = FakeSession(self._not_found)
        issues = self._WSS(session, "https://example.test", base, discover=False).scan()
        assert any(i["type"] == "Directory Listing Enabled" for i in issues)

    def test_no_response_returns_no_issues(self):
        session = FakeSession(self._not_found)
        issues = self._WSS(session, "https://example.test", None, discover=True).scan()
        assert issues == []


class TestScannerSchemeHandling:
    """Covers the HTTPS-fallback / SSL-check-skip regression."""

    def test_https_fails_falls_back_to_http_and_skips_ssl_check(self):
        from unittest.mock import patch, MagicMock
        import requests as req
        from secprobe.scanner import SecProbe

        def side_effect(url, *a, **kw):
            if url.startswith("https://"):
                raise req.exceptions.ConnectionError("no tls")
            return MagicMock(url=url, status_code=200,
                              headers={"Content-Type": "text/html"},
                              text="<html></html>", content=b"<html></html>", history=[])

        with patch("requests.Session.get", side_effect=side_effect):
            s = SecProbe("httponly.example.test", use_ai=False, discover=False)
            report = s.run()

        assert report["target"].startswith("http://")
        assert report["debug"]["used_https"] is False
        assert not any(i["category"] == "SSL/TLS" for i in report["issues"])
        assert any(i["type"] == "HTTPS Not Available" for i in report["issues"])

    def test_explicit_http_scheme_never_falls_back(self):
        from unittest.mock import patch
        import requests as req
        from secprobe.scanner import SecProbe

        with patch("requests.Session.get", side_effect=req.exceptions.ConnectionError("dead")) as m:
            s = SecProbe("http://dead.example.test", use_ai=False, discover=False)
            report = s.run()

        assert m.call_count == 1  # no fallback attempt for an explicit scheme
        assert report["debug"]["status_code"] is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
