"""GitHub Actions secrets destination (repository + environment scopes)."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import anyio
from nacl import encoding, public

from secretsync.destinations.base import (
    ApplyDestinationRequest,
    ApplyDestinationResult,
    BatchCapability,
    DestinationCapabilities,
    DestinationManifest,
    Issue,
    MutationResult,
    OperationContext,
    PutMutation,
    PutSemantics,
    SafeConnectorError,
)
from secretsync.domain.models import JsonValue
from secretsync.infrastructure.http import HttpRequestError, request_with_retries
from secretsync.infrastructure.redaction import scrub_bytearray

GITHUB_API = "https://api.github.com"
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
REPO_RE = re.compile(r"^[^/\s]+/[^/\s]+$")


def _capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=True,
        read_values=False,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(supported=False),
        delete_batch=BatchCapability(supported=False),
        multiple_scopes_per_mutation=False,
        batch_across_scopes=False,
    )


def encrypt_github_secret(public_key_b64: str, secret_value: bytes) -> str:
    """LibSodium sealed-box encryption for GitHub Actions secrets API."""
    public_key = public.PublicKey(public_key_b64.encode("utf-8"), encoding.Base64Encoder)
    sealed = public.SealedBox(public_key).encrypt(secret_value)
    return base64.b64encode(sealed).decode("utf-8")


def _parse_repository(config: Mapping[str, JsonValue]) -> tuple[str, str] | None:
    raw = config.get("repository")
    if not isinstance(raw, str) or not REPO_RE.match(raw):
        return None
    owner, repo = raw.split("/", 1)
    return owner, repo


def _token_env(config: Mapping[str, JsonValue]) -> str | None:
    auth = config.get("auth")
    if isinstance(auth, dict):
        token_env = auth.get("tokenEnv")
        if isinstance(token_env, str) and token_env:
            return token_env
    return None


def _scope_key(scope: Mapping[str, JsonValue]) -> str:
    kind = str(scope.get("kind", ""))
    if kind == "environment":
        return f"environment:{scope.get('environment', '')}"
    return "repository"


@dataclass
class GitHubActionsDestination:
    manifest: DestinationManifest
    environ: Mapping[str, str]
    http_client_factory: Any
    put_concurrency: int = 4
    _public_keys: dict[str, tuple[str, str]] = field(default_factory=dict)

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        issues: list[Issue] = []
        if _parse_repository(config) is None:
            issues.append(
                Issue(
                    code="DESTINATION_INVALID",
                    message="github-actions requires repository as 'owner/name'",
                )
            )
        if _token_env(config) is None:
            issues.append(
                Issue(
                    code="AUTH_MISSING",
                    message="github-actions requires auth.tokenEnv",
                )
            )
        return issues

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        config = request.destination_config
        parsed = _parse_repository(config)
        token_env = _token_env(config)
        if parsed is None or token_env is None:
            error = SafeConnectorError(
                code="DESTINATION_INVALID",
                message="Invalid github-actions destination configuration",
                correlation_id=context.correlation_id,
            )
            return ApplyDestinationResult(
                results=tuple(
                    MutationResult(m.mutation_id, "failed", None, error) for m in request.mutations
                ),
                requests_made=0,
            )

        token = self.environ.get(token_env)
        if not token:
            error = SafeConnectorError(
                code="AUTH_MISSING",
                message=f"Connector credential environment variable '{token_env}' is absent",
                correlation_id=context.correlation_id,
            )
            return ApplyDestinationResult(
                results=tuple(
                    MutationResult(m.mutation_id, "failed", None, error) for m in request.mutations
                ),
                requests_made=0,
            )

        owner, repo = parsed
        # Group by scope for public-key caching; still one PUT per mutation.
        by_scope: dict[str, list[PutMutation]] = {}
        for mutation in request.mutations:
            if not mutation.scopes:
                by_scope.setdefault("invalid", []).append(mutation)
                continue
            scope = dict(mutation.scopes[0])
            kind = scope.get("kind")
            if kind == "organization":
                by_scope.setdefault("organization", []).append(mutation)
            elif kind == "environment":
                if not scope.get("environment"):
                    by_scope.setdefault("invalid", []).append(mutation)
                else:
                    by_scope.setdefault(_scope_key(scope), []).append(mutation)
            elif kind == "repository":
                by_scope.setdefault(_scope_key(scope), []).append(mutation)
            else:
                by_scope.setdefault("invalid", []).append(mutation)

        results: dict[str, MutationResult] = {}
        requests_made = 0

        for mutation in by_scope.get("organization", []):
            results[mutation.mutation_id] = MutationResult(
                mutation_id=mutation.mutation_id,
                status="failed",
                error=SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Organization secrets are not supported in MVP",
                    mutation_id=mutation.mutation_id,
                    correlation_id=context.correlation_id,
                ),
            )
        for mutation in by_scope.get("invalid", []):
            results[mutation.mutation_id] = MutationResult(
                mutation_id=mutation.mutation_id,
                status="failed",
                error=SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Invalid GitHub scope; require kind repository|environment",
                    mutation_id=mutation.mutation_id,
                    correlation_id=context.correlation_id,
                ),
            )

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        client = self.http_client_factory.create(headers=headers)
        limiter = anyio.CapacityLimiter(self.put_concurrency)
        try:
            async with client:
                for scope_id, mutations in by_scope.items():
                    if scope_id in {"organization", "invalid"}:
                        continue
                    scope = dict(mutations[0].scopes[0])
                    try:
                        key_id, key_b64, key_requests = await self._get_public_key(
                            client, owner, repo, scope, context.correlation_id
                        )
                        requests_made += key_requests
                    except HttpRequestError as exc:
                        for mutation in mutations:
                            results[mutation.mutation_id] = MutationResult(
                                mutation_id=mutation.mutation_id,
                                status="failed",
                                error=exc.safe,
                            )
                        continue

                    async def put_one(
                        mutation: PutMutation,
                        put_scope: dict[str, JsonValue],
                        put_key_id: str,
                        put_key_b64: str,
                    ) -> None:
                        nonlocal requests_made
                        async with limiter:
                            result, n = await self._put_secret(
                                client,
                                owner,
                                repo,
                                put_scope,
                                mutation,
                                put_key_id,
                                put_key_b64,
                                context.correlation_id,
                            )
                            results[mutation.mutation_id] = result
                            requests_made += n

                    async with anyio.create_task_group() as tg:
                        for mutation in mutations:
                            tg.start_soon(put_one, mutation, scope, key_id, key_b64)
        finally:
            # Token must not linger in headers dict we created; client closed above.
            pass

        ordered = tuple(
            results.get(
                m.mutation_id,
                MutationResult(
                    mutation_id=m.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Connector omitted result for mutation",
                        mutation_id=m.mutation_id,
                        correlation_id=context.correlation_id,
                    ),
                ),
            )
            for m in request.mutations
        )
        return ApplyDestinationResult(results=ordered, requests_made=requests_made)

    async def _get_public_key(
        self,
        client: Any,
        owner: str,
        repo: str,
        scope: Mapping[str, JsonValue],
        correlation_id: str,
    ) -> tuple[str, str, int]:
        cache_key = _scope_key(scope)
        if cache_key in self._public_keys:
            key_id, key_b64 = self._public_keys[cache_key]
            return key_id, key_b64, 0

        kind = scope.get("kind")
        if kind == "environment":
            env_name = quote(str(scope["environment"]), safe="")
            url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/public-key"
        else:
            url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets/public-key"

        response = await request_with_retries(client, "GET", url, correlation_id=correlation_id)
        if response.status_code != 200:
            from secretsync.infrastructure.http import error_for_status

            raise HttpRequestError(
                error_for_status(response.status_code, correlation_id=correlation_id)
            )
        payload = response.json()
        key_id = str(payload["key_id"])
        key_b64 = str(payload["key"])
        self._public_keys[cache_key] = (key_id, key_b64)
        return key_id, key_b64, 1

    async def _put_secret(
        self,
        client: Any,
        owner: str,
        repo: str,
        scope: Mapping[str, JsonValue],
        mutation: PutMutation,
        key_id: str,
        key_b64: str,
        correlation_id: str,
    ) -> tuple[MutationResult, int]:
        if not SECRET_NAME_RE.match(mutation.name):
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=f"Invalid GitHub secret name '{mutation.name}'",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )

        ciphertext = bytearray()
        try:
            encrypted = encrypt_github_secret(key_b64, bytes(mutation.value))
            ciphertext.extend(encrypted.encode("utf-8"))
            kind = scope.get("kind")
            if kind == "environment":
                env_name = quote(str(scope["environment"]), safe="")
                url = (
                    f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}"
                    f"/secrets/{mutation.name}"
                )
            else:
                url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets/{mutation.name}"

            response = await request_with_retries(
                client,
                "PUT",
                url,
                mutation_id=mutation.mutation_id,
                correlation_id=correlation_id,
                json={"encrypted_value": encrypted, "key_id": key_id},
            )
            if response.status_code == 201:
                return (
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="applied",
                        effect="created",
                    ),
                    1,
                )
            if response.status_code == 204:
                return (
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="applied",
                        effect="updated",
                    ),
                    1,
                )
            from secretsync.infrastructure.http import error_for_status

            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=error_for_status(
                        response.status_code,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                1,
            )
        except HttpRequestError as exc:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                ),
                1,
            )
        finally:
            scrub_bytearray(ciphertext)


@dataclass(frozen=True, slots=True)
class GitHubActionsFactory:
    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="github-actions",
            version="0.1.0+actions-secrets",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> GitHubActionsDestination:
        return GitHubActionsDestination(
            manifest=self.manifest,
            environ=services.environ,
            http_client_factory=services.http_client_factory,
        )
