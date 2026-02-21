"""
Hancock Agent — Test Suite
Run:  make test   or   .venv/bin/pytest tests/ -v
"""
import json
import os
import sys
import pytest

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def app():
    """Create a Flask test app with a mocked OpenAI client."""
    from unittest.mock import MagicMock, patch

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "Mocked Hancock response."
    mock_client.chat.completions.create.return_value = mock_resp

    # Patch OpenAI before importing run_server
    with patch("hancock_agent.OpenAI", return_value=mock_client):
        import hancock_agent
        flask_app = hancock_agent.run_server.__wrapped__ if hasattr(
            hancock_agent.run_server, "__wrapped__") else None

        # Build app directly since run_server calls app.run()
        from flask import Flask
        import importlib
        # Re-import to get the Flask app instance via the factory
        app = hancock_agent.build_app(mock_client, "mistralai/mistral-7b-instruct-v0.3")
        app.testing = True
        return app


@pytest.fixture
def client(app):
    return app.test_client()


# ── /health ───────────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_returns_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_health_json_structure(self, client):
        data = r = client.get("/health").get_json()
        assert data["status"] == "ok"
        assert "model" in data
        assert "endpoints" in data

    def test_health_endpoints_list(self, client):
        data = client.get("/health").get_json()
        eps = data["endpoints"]
        assert "/v1/chat" in eps
        assert "/v1/triage" in eps
        assert "/v1/code" in eps


# ── /v1/ask ───────────────────────────────────────────────────────────────────

class TestAsk:
    def test_ask_returns_answer(self, client):
        r = client.post("/v1/ask",
                        data=json.dumps({"question": "What is Log4Shell?"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert "answer" in r.get_json()

    def test_ask_missing_question_returns_400(self, client):
        r = client.post("/v1/ask",
                        data=json.dumps({}),
                        content_type="application/json")
        assert r.status_code == 400
        assert "error" in r.get_json()

    def test_ask_empty_question_returns_400(self, client):
        r = client.post("/v1/ask",
                        data=json.dumps({"question": ""}),
                        content_type="application/json")
        assert r.status_code == 400


# ── /v1/triage ────────────────────────────────────────────────────────────────

class TestTriage:
    def test_triage_returns_result(self, client):
        r = client.post("/v1/triage",
                        data=json.dumps({"alert": "Mimikatz.exe on DC01"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert "triage" in r.get_json()

    def test_triage_missing_alert_returns_400(self, client):
        r = client.post("/v1/triage",
                        data=json.dumps({}),
                        content_type="application/json")
        assert r.status_code == 400


# ── /v1/hunt ─────────────────────────────────────────────────────────────────

class TestHunt:
    def test_hunt_returns_query(self, client):
        r = client.post("/v1/hunt",
                        data=json.dumps({"target": "lateral movement"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "query" in d
        assert d["siem"] == "splunk"  # default

    def test_hunt_custom_siem(self, client):
        r = client.post("/v1/hunt",
                        data=json.dumps({"target": "kerberoasting", "siem": "elastic"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["siem"] == "elastic"

    def test_hunt_missing_target_returns_400(self, client):
        r = client.post("/v1/hunt",
                        data=json.dumps({}),
                        content_type="application/json")
        assert r.status_code == 400


# ── /v1/respond ───────────────────────────────────────────────────────────────

class TestRespond:
    def test_respond_returns_playbook(self, client):
        r = client.post("/v1/respond",
                        data=json.dumps({"incident": "ransomware"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert "playbook" in r.get_json()

    def test_respond_missing_incident_returns_400(self, client):
        r = client.post("/v1/respond",
                        data=json.dumps({}),
                        content_type="application/json")
        assert r.status_code == 400


# ── /v1/code ─────────────────────────────────────────────────────────────────

class TestCode:
    def test_code_returns_result(self, client):
        r = client.post("/v1/code",
                        data=json.dumps({"task": "YARA rule for Emotet"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "code" in d
        assert "model" in d

    def test_code_with_language(self, client):
        r = client.post("/v1/code",
                        data=json.dumps({"task": "detect PtH", "language": "kql"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert r.get_json()["language"] == "kql"

    def test_code_missing_task_returns_400(self, client):
        r = client.post("/v1/code",
                        data=json.dumps({}),
                        content_type="application/json")
        assert r.status_code == 400


# ── /v1/webhook ───────────────────────────────────────────────────────────────

class TestWebhook:
    def test_webhook_triage_alert(self, client):
        r = client.post("/v1/webhook",
                        data=json.dumps({
                            "source": "splunk",
                            "alert": "Suspicious PowerShell execution on WORKSTATION01",
                            "severity": "high",
                        }),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert d["status"] == "triaged"
        assert "triage" in d

    def test_webhook_missing_alert_returns_400(self, client):
        r = client.post("/v1/webhook",
                        data=json.dumps({"source": "splunk"}),
                        content_type="application/json")
        assert r.status_code == 400
