from __future__ import annotations

from secretsync.infrastructure.redaction import (
    redact_text,
    sanitize_provider_message,
    scrub_bytearray,
)


def test_scrub_bytearray_overwrites() -> None:
    buf = bytearray(b"super-secret")
    scrub_bytearray(buf)
    assert len(buf) == 0


def test_redact_and_sanitize() -> None:
    text = "token=abc123 and more"
    assert redact_text(text, ["abc123"]) == "token=*** and more"
    assert "abc123" not in sanitize_provider_message(text, ["abc123"])
