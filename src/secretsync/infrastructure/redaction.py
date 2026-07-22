"""Redaction and secret buffer scrubbing helpers."""

from __future__ import annotations

SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
    }
)


def scrub_bytearray(buf: bytearray) -> None:
    """Best-effort overwrite of a mutable secret buffer."""
    for i in range(len(buf)):
        buf[i] = 0
    buf.clear()


def redact_text(text: str, secrets: list[str] | None = None) -> str:
    """Best-effort redaction of known secret substrings."""
    result = text
    for secret in secrets or []:
        if secret:
            result = result.replace(secret, "***")
    return result


def sanitize_provider_message(text: str, secrets: list[str] | None = None) -> str:
    """Sanitize provider/diagnostic text before placing it in SafeError messages."""
    return redact_text(text, secrets)
