"""httpx client factory with safe retries and bounded provider-error diagnostics."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import httpx
from loguru import logger

from secretsync.domain.errors import SafeError
from secretsync.infrastructure.redaction import SENSITIVE_HEADER_NAMES, sanitize_provider_message

RETRYABLE_STATUS = frozenset({429, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 5
BOUNDED_PROVIDER_ERROR = 512

# Spec alias: connector-facing errors are SafeError payloads.
SafeConnectorError = SafeError


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


def response_debug_meta(response: httpx.Response) -> dict[str, object]:
    """Value-free response metadata for diagnostics (never includes body)."""
    return {
        "status_code": response.status_code,
        "headers": redact_headers(response.headers),
    }


def provider_error_detail(
    response: httpx.Response,
    secrets: Sequence[str] | None = None,
) -> str | None:
    """Bounded, redacted provider error text for SafeError / audit / verbose logs."""
    raw = (response.text or "")[: BOUNDED_PROVIDER_ERROR * 2]
    if not raw.strip():
        return None

    detail: str | None = None
    try:
        payload = response.json()
    except (ValueError, httpx.DecodingError):
        payload = None

    if isinstance(payload, dict):
        message = payload.get("message")
        if isinstance(message, str) and message.strip():
            detail = message.strip()
        else:
            error = payload.get("error")
            if isinstance(error, dict):
                bits: list[str] = []
                code = error.get("code")
                emsg = error.get("message")
                if isinstance(code, str) and code.strip():
                    bits.append(code.strip())
                if isinstance(emsg, str) and emsg.strip():
                    bits.append(emsg.strip())
                if bits:
                    detail = ": ".join(bits)
            elif isinstance(error, str) and error.strip():
                detail = error.strip()

    if detail is None:
        detail = " ".join(raw.split())

    detail = sanitize_provider_message(detail, list(secrets) if secrets else None)
    if len(detail) > BOUNDED_PROVIDER_ERROR:
        detail = detail[:BOUNDED_PROVIDER_ERROR] + "…"
    return detail or None


def error_for_status(
    response_or_status: httpx.Response | int,
    *,
    mutation_id: str | None = None,
    correlation_id: str | None = None,
    secrets: Sequence[str] | None = None,
) -> SafeConnectorError:
    if isinstance(response_or_status, int):
        status_code = response_or_status
        response: httpx.Response | None = None
        detail: str | None = None
    else:
        response = response_or_status
        status_code = response.status_code
        detail = provider_error_detail(response, secrets)

    if response is not None:
        method = response.request.method if response.request else "?"
        logger.debug(
            "provider HTTP {} {} -> {}{}",
            method,
            response.url,
            status_code,
            f": {detail}" if detail else "",
        )

    if status_code in {401, 403}:
        base = f"Provider rejected authorization (HTTP {status_code})"
        code = "DESTINATION_PERMISSION_DENIED"
        retryable = False
    elif status_code == 429:
        base = "Provider rate limit remained after bounded retry"
        code = "DESTINATION_RATE_LIMITED"
        retryable = True
    else:
        base = f"Provider rejected request (HTTP {status_code})"
        code = "DESTINATION_INVALID"
        retryable = False

    return SafeConnectorError(
        code=code,
        message=f"{base}: {detail}" if detail else base,
        mutation_id=mutation_id,
        correlation_id=correlation_id,
        retryable=retryable,
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
        # Touch redacted meta so sensitive headers are never kept as a logging side channel.
        _ = response_debug_meta(response)
        if attempt + 1 >= max_attempts:
            break
        await asyncio.sleep(_retry_delay_seconds(attempt, response))

    if last_response is not None:
        raise HttpRequestError(
            error_for_status(
                last_response,
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
