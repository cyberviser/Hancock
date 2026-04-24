from __future__ import annotations

from security.authz import Scope


def list_tools(mode: str, scopes: list[Scope], stage: str) -> list[str]:
    del stage
    del scopes
    mode_tools = {
        "pentest": ["nmap", "sqlmap"],
        "osint": ["nmap"],
        "soc": ["nmap"],
    }
    return mode_tools.get(mode, ["nmap"])
