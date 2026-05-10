"""
SecProbe - Unit Tests
Run: python -m pytest tests/ -v
"""

import pytest, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secprobe.scanner import SecProbe
from secprobe.modules.headers import HeaderScanner
from secprobe.modules.ai_explainer import AIExplainer, OfflineExplainer


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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
