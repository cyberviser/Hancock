"""Unit tests for Python SDK HancockClient."""
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "clients", "python"))


class TestHancockClient:
    """Tests for HancockClient (mocked NVIDIA NIM calls)."""

    @pytest.fixture
    def client(self, monkeypatch):
        from unittest.mock import MagicMock, patch
        mock_openai = MagicMock()
        mock_resp   = MagicMock()
        mock_resp.choices[0].message.content = "Mocked SDK response."
        mock_openai.return_value.chat.completions.create.return_value = mock_resp

        with patch("hancock_client.OpenAI", mock_openai):
            from hancock_client import HancockClient
            return HancockClient(api_key="nvapi-test-key")

    def test_ask_returns_string(self, client):
        result = client.ask("What is CVE-2021-44228?")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_ask_pentest_mode(self, client):
        result = client.ask("How to enumerate SMB shares?", mode="pentest")
        assert isinstance(result, str)

    def test_ask_soc_mode(self, client):
        result = client.ask("Triage Mimikatz alert", mode="soc")
        assert isinstance(result, str)

    def test_code_returns_string(self, client):
        result = client.code("Write a YARA rule for Emotet")
        assert isinstance(result, str)

    def test_code_with_language(self, client):
        result = client.code("Detect PtH", language="kql")
        assert isinstance(result, str)

    def test_triage_returns_string(self, client):
        result = client.triage("Mimikatz.exe on DC01 at 03:14 UTC")
        assert isinstance(result, str)

    def test_hunt_returns_string(self, client):
        result = client.hunt("Kerberoasting", siem="splunk")
        assert isinstance(result, str)

    def test_hunt_elastic(self, client):
        result = client.hunt("lateral movement", siem="elastic")
        assert isinstance(result, str)

    def test_respond_returns_string(self, client):
        result = client.respond("ransomware")
        assert isinstance(result, str)

    def test_chat_returns_string(self, client):
        result = client.chat("Hello, who are you?")
        assert isinstance(result, str)

    def test_chat_with_history(self, client):
        history = [
            {"role": "user",      "content": "What is Log4Shell?"},
            {"role": "assistant", "content": "Log4Shell is CVE-2021-44228..."},
        ]
        result = client.chat("How do I detect it?", history=history)
        assert isinstance(result, str)

    def test_no_api_key_raises(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
        from hancock_client import HancockClient
        with pytest.raises(ValueError, match="NVIDIA_API_KEY"):
            HancockClient()

    def test_model_alias_resolves(self):
        from unittest.mock import MagicMock, patch
        mock_openai = MagicMock()
        mock_resp   = MagicMock()
        mock_resp.choices[0].message.content = "ok"
        mock_openai.return_value.chat.completions.create.return_value = mock_resp
        with patch("hancock_client.OpenAI", mock_openai):
            from hancock_client import HancockClient, MODELS
            c = HancockClient(api_key="test", model="mixtral-8x7b")
            assert c.model == MODELS["mixtral-8x7b"]

    def test_sigma_returns_string(self, client):
        result = client.sigma("Detect LSASS memory dump")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_sigma_with_logsource_and_technique(self, client):
        result = client.sigma(
            "Kerberoasting via Rubeus",
            logsource="windows security",
            technique="T1558.003",
        )
        assert isinstance(result, str)

    def test_ciso_returns_string(self, client):
        result = client.ciso("What is NIST CSF 2.0?")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_ciso_output_types(self, client):
        for output in ["advice", "report", "gap-analysis", "board-summary"]:
            result = client.ciso("ISO 27001 gap analysis", output=output)
            assert isinstance(result, str)

    def test_ciso_with_context(self, client):
        result = client.ciso(
            "What controls should we prioritise?",
            output="gap-analysis",
            context="50-person SaaS, AWS, no certifications",
        )
        assert isinstance(result, str)
