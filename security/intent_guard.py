from __future__ import annotations

from typing import Any

from security.authz import Scope

DISALLOWED = {
    "ransomware",
    "ddos",
    "unauthorized",
    "bypass payment",
    "exploit prod without permission",
}
ALLOWED_MODES = {"pentest", "soc", "sigma", "yara", "ioc", "osint", "graphql", "code", "ciso", "auto"}


def verify_intent_and_scope(goal: str, mode: str, scopes: list[Scope]) -> None:
    lowered = (goal or "").lower()
    if any(term in lowered for term in DISALLOWED):
        raise PermissionError("Intent not authorized by policy.")

    scope_names = {scope.name for scope in scopes}
    if "authorized" not in scope_names:
        raise PermissionError("No authorized testing scope provided.")

    if mode not in ALLOWED_MODES:
        raise PermissionError("Unknown mode.")


def gate_actions(actions: list[dict[str, Any]], mode: str, scopes: list[Scope]) -> list[dict[str, Any]]:
    """Return low-risk actions in recommendation-only mode by default."""
    del mode
    del scopes

    allowed: list[dict[str, Any]] = []
    for stage in actions:
        allowed.append(
            {
                "stage": stage.get("stage", "unknown"),
                "suggestions": stage.get("suggestions", []),
                "execute": False,
            }
        )
    return allowed
