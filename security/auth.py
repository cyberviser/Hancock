from __future__ import annotations

import os


def parse_api_keys() -> set[str]:
    keys = set()
    for key in os.getenv("HANCOCK_API_KEYS", "").split(","):
        stripped = key.strip()
        if stripped:
            keys.add(stripped)

    # Backward-compatible single key support.
    single_key = os.getenv("HANCOCK_API_KEY", "").strip()
    if single_key:
        keys.add(single_key)

    return keys


def require_api_key(header_key: str) -> bool:
    configured = parse_api_keys()
    if not configured:
        # Preserve existing behavior: auth disabled when no key configured.
        return True
    return bool(header_key and header_key in configured)
