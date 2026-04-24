import os

from security.auth import parse_api_keys, require_api_key


def test_parse_api_keys_supports_csv_and_single_key(monkeypatch):
    monkeypatch.setenv("HANCOCK_API_KEYS", "k1,k2")
    monkeypatch.setenv("HANCOCK_API_KEY", "k3")
    assert parse_api_keys() == {"k1", "k2", "k3"}


def test_require_api_key_when_configured(monkeypatch):
    monkeypatch.setenv("HANCOCK_API_KEYS", "abc")
    monkeypatch.delenv("HANCOCK_API_KEY", raising=False)
    assert require_api_key("abc") is True
    assert require_api_key("wrong") is False


def test_require_api_key_disabled_when_unset(monkeypatch):
    monkeypatch.delenv("HANCOCK_API_KEYS", raising=False)
    monkeypatch.delenv("HANCOCK_API_KEY", raising=False)
    assert require_api_key("") is True
