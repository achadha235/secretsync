"""Minimal redaction helpers for safe presentation."""

from __future__ import annotations

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
    }
)


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    """Best-effort redaction of known secret substrings."""
    result = text
    for secret in secrets or []:
        if secret:
            result = result.replace(secret, "***")
    return result
