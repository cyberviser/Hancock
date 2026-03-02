"""Shared constants for Hancock modules."""

OPENAI_IMPORT_ERROR_MSG = "OpenAI client not installed. Run: pip install openai"


def require_openai(openai_cls):
    """Raise ImportError when the OpenAI dependency is missing."""
    if openai_cls is None:
        raise ImportError(OPENAI_IMPORT_ERROR_MSG)
