from __future__ import annotations

from pydantic import BaseModel, Field


class Scope(BaseModel):
    """Represents an authorization scope for a request."""

    name: str
    metadata: dict = Field(default_factory=dict)
