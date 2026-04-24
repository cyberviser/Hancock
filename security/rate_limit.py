from __future__ import annotations

import os


def parse_rate_limits() -> tuple[int, int]:
    """Return per-minute and per-hour limits with environment overrides."""
    per_minute = int(os.getenv("HANCOCK_RATE_LIMIT_AGENTIC_PER_MINUTE", "30"))
    per_hour = int(os.getenv("HANCOCK_RATE_LIMIT_AGENTIC_PER_HOUR", "2000"))
    return per_minute, per_hour
