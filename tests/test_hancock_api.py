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


# ── /v1/ciso ─────────────────────────────────────────────────────────────────

class TestCISO:
    def test_ciso_returns_advice(self, client):
        r = client.post("/v1/ciso",
                        data=json.dumps({"question": "What is NIST CSF 2.0?"}),
                        content_type="application/json")
        assert r.status_code == 200
        d = r.get_json()
        assert "advice" in d
        assert "model" in d
        assert d["output"] == "advice"

    def test_ciso_message_alias(self, client):
        """Accepts 'message' field as alias for 'question'."""
        r = client.post("/v1/ciso",
                        data=json.dumps({"message": "Explain SOC 2 Type II"}),
                        content_type="application/json")
        assert r.status_code == 200
        assert "advice" in r.get_json()

    def test_ciso_output_types(self, client):
        for output in ["advice", "report", "gap-analysis", "board-summary"]:
            r = client.post("/v1/ciso",
                            data=json.dumps({
                                "question": "ISO 27001 gap analysis",
                                "output": output,
                            }),
                            content_type="application/json")
            assert r.status_code == 200, f"output='{output}' should succeed"
            assert r.get_json()["output"] == output

    def test_ciso_with_context(self, client):
        r = client.post("/v1/ciso",
                        data=json.dumps({
                            "question": "What controls should we prioritise?",
                            "context": "50-person SaaS, AWS, no certifications",
                            "output": "gap-analysis",
                        }),
                        content_type="application/json")
        assert r.status_code == 200

    def test_ciso_missing_question_returns_400(self, client):
        r = client.post("/v1/ciso",
                        data=json.dumps({}),
                        content_type="application/json")
        assert r.status_code == 400
        assert "error" in r.get_json()


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


# ── Auth (HANCOCK_API_KEY) ────────────────────────────────────────────────────

class TestAuth:
    @pytest.fixture
    def secured_app(self):
        """App with HANCOCK_API_KEY set."""
        from unittest.mock import MagicMock, patch
        import os

        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "Secured response."
        mock_client.chat.completions.create.return_value = mock_resp

        with patch.dict(os.environ, {"HANCOCK_API_KEY": "test-secret-token"}):
            with patch("hancock_agent.OpenAI", return_value=mock_client):
                import hancock_agent
                import importlib
                importlib.reload(hancock_agent)
                app = hancock_agent.build_app(mock_client, "mistralai/mistral-7b-instruct-v0.3")
                app.testing = True
                return app

    def test_no_token_returns_401(self, secured_app):
        c = secured_app.test_client()
        r = c.post("/v1/ask",
                   data=json.dumps({"question": "test"}),
                   content_type="application/json")
        assert r.status_code == 401
        assert "error" in r.get_json()

    def test_wrong_token_returns_401(self, secured_app):
        c = secured_app.test_client()
        r = c.post("/v1/ask",
                   data=json.dumps({"question": "test"}),
                   content_type="application/json",
                   headers={"Authorization": "Bearer wrong-token"})
        assert r.status_code == 401

    def test_correct_token_succeeds(self, secured_app):
        c = secured_app.test_client()
        r = c.post("/v1/ask",
                   data=json.dumps({"question": "test"}),
                   content_type="application/json",
                   headers={"Authorization": "Bearer test-secret-token"})
        assert r.status_code == 200

    def test_health_bypasses_auth(self, secured_app):
        """Health endpoint should always be reachable."""
        c = secured_app.test_client()
        r = c.get("/health")
        assert r.status_code == 200


# ── Rate limiting ─────────────────────────────────────────────────────────────

class TestRateLimit:
    @pytest.fixture
    def tight_app(self):
        """App with a 3 req/min rate limit."""
        from unittest.mock import MagicMock, patch
        import os

        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = "response"
        mock_client.chat.completions.create.return_value = mock_resp

        with patch.dict(os.environ, {"HANCOCK_RATE_LIMIT": "3"}):
            with patch("hancock_agent.OpenAI", return_value=mock_client):
                import hancock_agent
                import importlib
                importlib.reload(hancock_agent)
                app = hancock_agent.build_app(mock_client, "mistralai/mistral-7b-instruct-v0.3")
                app.testing = True
                return app

    def test_rate_limit_blocks_on_exceed(self, tight_app):
        c = tight_app.test_client()
        payload = json.dumps({"question": "test"})
        ct = "application/json"
        for _ in range(3):
            r = c.post("/v1/ask", data=payload, content_type=ct)
            assert r.status_code == 200
        # 4th request should be rate-limited
        r = c.post("/v1/ask", data=payload, content_type=ct)
        assert r.status_code == 429
        assert "Rate limit" in r.get_json()["error"]


# ── Input validation ──────────────────────────────────────────────────────────

class TestChatValidation:
    def test_invalid_mode_returns_400(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "hello", "mode": "hacker"}),
                        content_type="application/json")
        assert r.status_code == 400
        assert "invalid mode" in r.get_json()["error"]

    def test_invalid_history_type_returns_400(self, client):
        r = client.post("/v1/chat",
                        data=json.dumps({"message": "hello", "history": "bad"}),
                        content_type="application/json")
        assert r.status_code == 400
        assert "history" in r.get_json()["error"]

    def test_valid_modes_succeed(self, client):
        for mode in ["pentest", "soc", "auto", "code"]:
            r = client.post("/v1/chat",
                            data=json.dumps({"message": "test", "mode": mode}),
                            content_type="application/json")
            assert r.status_code == 200, f"mode '{mode}' should succeed"

    def test_empty_response_returns_502(self, client, app):
        """Model returning empty string should yield 502."""
        from unittest.mock import MagicMock, patch
        mock_resp = MagicMock()
        mock_resp.choices[0].message.content = ""
        # Patch the client used inside the app
        with patch.object(app, "test_client") as _:
            pass  # just verify the validation path exists by checking behavior
        # Direct test via a fresh app with empty-response mock
        from unittest.mock import MagicMock
        import hancock_agent
        empty_client = MagicMock()
        empty_resp = MagicMock()
        empty_resp.choices[0].message.content = ""
        empty_client.chat.completions.create.return_value = empty_resp
        fresh_app = hancock_agent.build_app(empty_client, "mistralai/mistral-7b-instruct-v0.3")
        fresh_app.testing = True
        c = fresh_app.test_client()
        r = c.post("/v1/chat",
                   data=json.dumps({"message": "hello"}),
                   content_type="application/json")
        assert r.status_code == 502


# ── OpenAI fallback ───────────────────────────────────────────────────────────

class TestOpenAIFallback:
    def test_fallback_function_returns_openai_response(self):
        """When NIM raises, chat() auto-falls back to OpenAI client."""
        from unittest.mock import MagicMock, patch
        import os
        import hancock_agent

        nim_client = MagicMock()
        nim_client.chat.completions.create.side_effect = Exception("NIM unavailable")

        openai_resp = MagicMock()
        openai_resp.choices[0].message.content = "Fallback response."
        openai_client = MagicMock()
        openai_client.chat.completions.create.return_value = openai_resp

        msgs = [{"role": "user", "content": "test"}]
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("hancock_agent.make_openai_client", return_value=openai_client):
                result = hancock_agent.chat(nim_client, msgs,
                                            "mistralai/mistral-7b-instruct-v0.3",
                                            stream=False)
        assert result == "Fallback response."
        openai_client.chat.completions.create.assert_called_once()

    def test_fallback_raises_when_both_fail(self):
        """When both NIM and OpenAI are unavailable, chat() propagates the exception."""
        from unittest.mock import MagicMock, patch
        import hancock_agent

        nim_client = MagicMock()
        nim_client.chat.completions.create.side_effect = Exception("NIM down")

        msgs = [{"role": "user", "content": "test"}]
        with patch("hancock_agent.make_openai_client", return_value=None):
            with pytest.raises(Exception, match="NIM down"):
                hancock_agent.chat(nim_client, msgs,
                                   "mistralai/mistral-7b-instruct-v0.3",
                                   stream=False)
