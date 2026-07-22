"""httpx client factory with safe retries and no wire logging."""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from typing import Any

import httpx

from secretsync.destinations.base import SafeConnectorError
from secretsync.infrastructure.redaction import SENSITIVE_HEADER_NAMES

RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 5


@dataclass(frozen=True, slots=True)
class HttpClientFactory:
    """Creates AsyncClients with wire logging disabled."""

    timeout: httpx.Timeout = field(default_factory=lambda: httpx.Timeout(30.0, connect=10.0))

    def create(self, *, headers: dict[str, str] | None = None) -> httpx.AsyncClient:
        # Intentionally no event_hooks that could capture bodies or Authorization.
        return httpx.AsyncClient(
            timeout=self.timeout,
            headers=headers or {},
            follow_redirects=True,
        )


def redact_headers(headers: httpx.Headers | MappingLike) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_NAMES:
            result[key] = "***"
        else:
            result[key] = value
    return result


MappingLike = Any


def error_for_status(
    status_code: int,
    *,
    mutation_id: str | None = None,
    correlation_id: str | None = None,
) -> SafeConnectorError:
    if status_code in {401, 403}:
        return SafeConnectorError(
            code="DESTINATION_PERMISSION_DENIED",
            message=f"Provider rejected authorization (HTTP {status_code})",
            mutation_id=mutation_id,
            correlation_id=correlation_id,
            retryable=False,
        )
    if status_code == 429:
        return SafeConnectorError(
            code="DESTINATION_RATE_LIMITED",
            message="Provider rate limit remained after bounded retry",
            mutation_id=mutation_id,
            correlation_id=correlation_id,
            retryable=True,
        )
    return SafeConnectorError(
        code="DESTINATION_INVALID",
        message=f"Provider rejected request (HTTP {status_code})",
        mutation_id=mutation_id,
        correlation_id=correlation_id,
        retryable=False,
    )


def _retry_delay_seconds(attempt: int, response: httpx.Response | None) -> float:
    """Full-jitter exponential backoff; honor Retry-After when present."""
    if response is not None:
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            try:
                return max(0.0, float(retry_after))
            except ValueError:
                pass
    base = min(2**attempt, 16)
    return random.uniform(0, base)


async def request_with_retries(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    mutation_id: str | None = None,
    correlation_id: str | None = None,
    **kwargs: Any,
) -> httpx.Response:
    """Perform an HTTP request with bounded retries for idempotent transient failures."""
    last_response: httpx.Response | None = None
    last_exc: Exception | None = None
    for attempt in range(max_attempts):
        try:
            response = await client.request(method, url, **kwargs)
        except httpx.TransportError as exc:
            last_exc = exc
            if attempt + 1 >= max_attempts:
                break
            await asyncio.sleep(_retry_delay_seconds(attempt, None))
            continue

        if response.status_code not in RETRYABLE_STATUS:
            return response

        last_response = response
        if attempt + 1 >= max_attempts:
            break
        await asyncio.sleep(_retry_delay_seconds(attempt, response))

    if last_response is not None:
        raise HttpRequestError(
            error_for_status(
                last_response.status_code,
                mutation_id=mutation_id,
                correlation_id=correlation_id,
            )
        )
    raise HttpRequestError(
        SafeConnectorError(
            code="DESTINATION_INVALID",
            message=f"HTTP transport failed after retries: {type(last_exc).__name__}",
            mutation_id=mutation_id,
            correlation_id=correlation_id,
            retryable=True,
        )
    )


class HttpRequestError(Exception):
    def __init__(self, safe: SafeConnectorError) -> None:
        self.safe = safe
        super().__init__(safe.message)
