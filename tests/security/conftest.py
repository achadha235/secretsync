"""Shared canary helpers for security suites."""

from __future__ import annotations

from pathlib import Path

CANARY = "SECRET_CANARY_a9f731"
CANARY_BYTES = CANARY.encode("utf-8")

FAKE_ENV = {
    "YB_DATABASE_URL": CANARY,
    "STRIPE_SECRET_KEY": "sk_live_canary_sibling",
    "API_TOKEN": "token_canary_sibling",
}


def assert_canary_absent(text: str | bytes, *, label: str = "output") -> None:
    blob = text if isinstance(text, bytes) else text.encode("utf-8", errors="replace")
    assert CANARY_BYTES not in blob, f"canary leaked into {label}"
    assert b"sk_live_canary_sibling" not in blob, f"sibling secret leaked into {label}"
    assert b"token_canary_sibling" not in blob, f"token canary leaked into {label}"


def assert_no_canary_under(path: Path) -> None:
    for file_path in path.rglob("*"):
        if file_path.is_file():
            assert_canary_absent(file_path.read_bytes(), label=str(file_path))
