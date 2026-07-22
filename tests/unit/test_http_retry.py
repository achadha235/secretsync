from __future__ import annotations

import httpx
import pytest
import respx

from secretsync.infrastructure.http import HttpRequestError, request_with_retries


@pytest.mark.asyncio
@respx.mock
async def test_retries_429_then_succeeds() -> None:
    route = respx.get("https://example.test/resource").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "0"}),
            httpx.Response(200, json={"ok": True}),
        ]
    )
    async with httpx.AsyncClient() as client:
        response = await request_with_retries(client, "GET", "https://example.test/resource")
    assert response.status_code == 200
    assert route.call_count == 2


@pytest.mark.asyncio
@respx.mock
async def test_non_retryable_401_returns_immediately() -> None:
    route = respx.get("https://example.test/secure").mock(return_value=httpx.Response(401))
    async with httpx.AsyncClient() as client:
        response = await request_with_retries(client, "GET", "https://example.test/secure")
    assert response.status_code == 401
    assert route.call_count == 1


@pytest.mark.asyncio
@respx.mock
async def test_exhausted_retries_raise_rate_limited() -> None:
    respx.get("https://example.test/limited").mock(return_value=httpx.Response(429))
    async with httpx.AsyncClient() as client:
        with pytest.raises(HttpRequestError) as exc:
            await request_with_retries(
                client,
                "GET",
                "https://example.test/limited",
                max_attempts=3,
            )
    assert exc.value.safe.code == "DESTINATION_RATE_LIMITED"


@pytest.mark.asyncio
@respx.mock
async def test_400_not_retried() -> None:
    route = respx.post("https://example.test/bad").mock(return_value=httpx.Response(400))
    async with httpx.AsyncClient() as client:
        response = await request_with_retries(client, "POST", "https://example.test/bad")
    assert response.status_code == 400
    assert route.call_count == 1
