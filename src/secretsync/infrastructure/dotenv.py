"""Streaming dotenv encoder for SST secret load (no mega-string logging)."""

from __future__ import annotations

from collections.abc import Callable, Mapping

WriteFn = Callable[[bytes], None]


class DotenvEncodeError(ValueError):
    """Raised for invalid dotenv keys or values (safe message, no secret bytes)."""


def validate_dotenv_key(key: str) -> None:
    if not key:
        raise DotenvEncodeError("dotenv key must be non-empty")
    if "=" in key:
        raise DotenvEncodeError("dotenv key must not contain '='")
    if "\n" in key or "\r" in key:
        raise DotenvEncodeError("dotenv key must not contain line breaks")
    if "\x00" in key:
        raise DotenvEncodeError("dotenv key must not contain NUL")


def quote_dotenv_value(value: bytes | bytearray) -> bytes:
    """Quote a value using a deterministic double-quoted dotenv dialect."""
    if b"\x00" in value:
        raise DotenvEncodeError("dotenv value must not contain NUL")
    text = bytes(value).decode("utf-8")
    escaped: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch == "\\":
            escaped.append("\\\\")
        elif ch == '"':
            escaped.append('\\"')
        elif ch == "\n":
            escaped.append("\\n")
        elif ch == "\r":
            escaped.append("\\r")
        elif ch == "\t":
            escaped.append("\\t")
        elif code < 0x20:
            escaped.append(f"\\x{code:02x}")
        else:
            escaped.append(ch)
    return ('"' + "".join(escaped) + '"').encode("utf-8")


def stream_dotenv(
    variables: Mapping[str, bytes | bytearray],
    write: WriteFn,
) -> None:
    """Stream KEY="value" lines to write(); does not retain a combined secret string."""
    for key in variables:
        validate_dotenv_key(key)
        write(key.encode("utf-8"))
        write(b"=")
        write(quote_dotenv_value(variables[key]))
        write(b"\n")
