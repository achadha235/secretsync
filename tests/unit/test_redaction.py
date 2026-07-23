from __future__ import annotations

from secretsync.infrastructure.redaction import (
    SENSITIVE_HEADER_NAMES,
    redact_text,
    sanitize_provider_message,
    scrub_bytearray,
)

CANARY = "SECRET_CANARY_redact_a9f731"


def test_scrub_bytearray_overwrites() -> None:
    buf = bytearray(b"super-secret")
    scrub_bytearray(buf)
    assert len(buf) == 0
    assert b"super-secret" not in buf


def test_redact_and_sanitize() -> None:
    text = f"token={CANARY} and more"
    assert redact_text(text, [CANARY]) == "token=*** and more"
    assert CANARY not in sanitize_provider_message(text, [CANARY])


def test_redact_skips_empty_and_none_secrets() -> None:
    text = f"keep {CANARY}"
    assert redact_text(text, None) == text
    assert redact_text(text, []) == text
    assert redact_text(text, ["", CANARY]) == "keep ***"
    assert "authorization" in SENSITIVE_HEADER_NAMES
