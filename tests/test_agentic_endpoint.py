import os
import sys
from unittest.mock import MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))



def _build_app_with_key(api_keys: str = "test-key"):
    import importlib

    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = "ok"
    mock_client.chat.completions.create.return_value = mock_resp

    os.environ["HANCOCK_API_KEYS"] = api_keys
    import hancock_agent

    importlib.reload(hancock_agent)
    app = hancock_agent.build_app(mock_client, "mock-model")
    app.testing = True
    return app


def test_agentic_run_requires_api_key():
    app = _build_app_with_key("k1")
    client = app.test_client()
    resp = client.post("/v1/agentic/run", json={"goal": "safe goal", "scopes": ["authorized"], "mode": "pentest"})
    assert resp.status_code == 401


def test_agentic_run_returns_report_with_valid_key():
    app = _build_app_with_key("k1")
    client = app.test_client()
    resp = client.post(
        "/v1/agentic/run",
        headers={"X-API-Key": "k1"},
        json={"goal": "safe goal", "scopes": ["authorized"], "mode": "pentest", "history": []},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "report" in body
    assert "risk" in body
