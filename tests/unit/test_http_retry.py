from __future__ import annotations

import httpx
import pytest
import respx

from secretsync.infrastructure.http import (
    HttpRequestError,
    error_for_status,
    provider_error_detail,
    request_with_retries,
)


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
    respx.get("https://example.test/limited").mock(
        return_value=httpx.Response(429, json={"message": "slow down"})
    )
    async with httpx.AsyncClient() as client:
        with pytest.raises(HttpRequestError) as exc:
            await request_with_retries(
                client,
                "GET",
                "https://example.test/limited",
                max_attempts=3,
            )
    assert exc.value.safe.code == "DESTINATION_RATE_LIMITED"
    assert "slow down" in exc.value.safe.message


@pytest.mark.asyncio
@respx.mock
async def test_400_not_retried() -> None:
    route = respx.post("https://example.test/bad").mock(return_value=httpx.Response(400))
    async with httpx.AsyncClient() as client:
        response = await request_with_retries(client, "POST", "https://example.test/bad")
    assert response.status_code == 400
    assert route.call_count == 1


def test_error_for_status_includes_github_message() -> None:
    response = httpx.Response(
        404,
        json={"message": "Not Found", "documentation_url": "https://docs.github.com"},
        request=httpx.Request("PUT", "https://api.github.com/orgs/acme/actions/secrets/X"),
    )
    err = error_for_status(response, correlation_id="c1")
    assert err.code == "DESTINATION_INVALID"
    assert err.message == "Provider rejected request (HTTP 404): Not Found"


def test_error_for_status_includes_vercel_error() -> None:
    response = httpx.Response(
        400,
        json={"error": {"code": "bad_request", "message": "Invalid key"}},
        request=httpx.Request("POST", "https://api.vercel.com/v10/projects/p/env"),
    )
    err = error_for_status(response)
    assert "bad_request: Invalid key" in err.message


def test_provider_error_detail_redacts_secrets() -> None:
    response = httpx.Response(400, json={"message": "value sk_live_x is invalid"})
    detail = provider_error_detail(response, secrets=["sk_live_x"])
    assert detail is not None
    assert "sk_live_x" not in detail
    assert "***" in detail
