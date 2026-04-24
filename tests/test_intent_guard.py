import pytest

from security.authz import Scope
from security.intent_guard import gate_actions, verify_intent_and_scope


def test_verify_intent_allows_authorized_scope():
    verify_intent_and_scope("Enumerate public assets for example.com", "pentest", [Scope(name="authorized")])


def test_verify_intent_blocks_disallowed_term():
    with pytest.raises(PermissionError):
        verify_intent_and_scope("Launch ddos", "pentest", [Scope(name="authorized")])


def test_gate_actions_defaults_to_no_execute():
    gated = gate_actions([{"stage": "recon", "suggestions": ["do thing"]}], "pentest", [Scope(name="authorized")])
    assert gated[0]["execute"] is False
