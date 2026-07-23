from __future__ import annotations

import httpx

from secretsync.infrastructure.http import redact_headers, response_debug_meta

CANARY = "SECRET_CANARY_hdr_a9f731"


def test_redact_headers_sensitive_names() -> None:
    headers = httpx.Headers(
        {
            "Authorization": f"Bearer {CANARY}",
            "Cookie": f"session={CANARY}",
            "Set-Cookie": f"t={CANARY}",
            "X-Api-Key": CANARY,
            "X-Request-Id": "req-1",
            "Content-Type": "application/json",
        }
    )
    redacted = redact_headers(headers)
    # httpx.Headers normalizes keys to lowercase when iterating.
    assert redacted["authorization"] == "***"
    assert redacted["cookie"] == "***"
    assert redacted["set-cookie"] == "***"
    assert redacted["x-api-key"] == "***"
    assert redacted["x-request-id"] == "req-1"
    assert redacted["content-type"] == "application/json"
    assert CANARY not in str(redacted)


def test_redact_headers_mapping_like() -> None:
    raw = {"authorization": f"token {CANARY}", "accept": "application/json"}
    out = redact_headers(raw)
    assert out["authorization"] == "***"
    assert out["accept"] == "application/json"
    assert CANARY not in out["authorization"]


def test_response_debug_meta_value_free() -> None:
    response = httpx.Response(
        429,
        headers={
            "Authorization": f"Bearer {CANARY}",
            "Retry-After": "1",
        },
        content=b'{"secret":"' + CANARY.encode() + b'"}',
        request=httpx.Request("GET", "https://example.test/x"),
    )
    meta = response_debug_meta(response)
    assert meta["status_code"] == 429
    assert isinstance(meta["headers"], dict)
    headers = meta["headers"]
    assert headers["authorization"] == "***"
    assert headers["retry-after"] == "1"
    assert "body" not in meta
    assert CANARY not in str(meta)
    assert CANARY.encode() not in repr(meta).encode()
