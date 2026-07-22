from __future__ import annotations

import pytest

from secretsync.infrastructure.dotenv import (
    DotenvEncodeError,
    quote_dotenv_value,
    stream_dotenv,
    validate_dotenv_key,
)


def test_quote_and_empty() -> None:
    assert quote_dotenv_value(b"") == b'""'
    assert quote_dotenv_value(b'a"b') == b'"a\\"b"'
    assert quote_dotenv_value(b"a\\b") == b'"a\\\\b"'
    assert quote_dotenv_value(b"a\nb") == b'"a\\nb"'


def test_reject_bad_keys() -> None:
    with pytest.raises(DotenvEncodeError):
        validate_dotenv_key("A=B")
    with pytest.raises(DotenvEncodeError):
        validate_dotenv_key("A\nB")
    with pytest.raises(DotenvEncodeError):
        validate_dotenv_key("A\x00B")


def test_stream_dotenv_chunks() -> None:
    chunks: list[bytes] = []
    stream_dotenv({"FOO": b"bar", "EMPTY": b""}, chunks.append)
    assert b"".join(chunks) == b'FOO="bar"\nEMPTY=""\n'


def test_stream_rejects_nul_value() -> None:
    with pytest.raises(DotenvEncodeError):
        stream_dotenv({"FOO": b"a\x00b"}, lambda _c: None)
