"""GitHub Actions secrets destination (repository, environment, organization scopes)."""

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
    DeleteMutation,
    DestinationCapabilities,
    DestinationManifest,
    Issue,
    ListNamesError,
    MutationResult,
    OperationContext,
    PutMutation,
    PutSemantics,
    SafeConnectorError,
)
from secretsync.domain.models import JsonValue, ValueKind
from secretsync.infrastructure.http import HttpRequestError, request_with_retries
from secretsync.infrastructure.redaction import scrub_bytearray

GITHUB_API = "https://api.github.com"
SECRET_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
OWNER_REPO_RE = re.compile(r"^[^/\s]+/[^/\s]+$")
SEGMENT_RE = re.compile(r"^[^/\s]+$")
VARIABLE_NAME_RE = SECRET_NAME_RE
# Backward-compatible alias used by older tests / callers.
REPO_RE = OWNER_REPO_RE
ORG_VISIBILITIES = frozenset({"all", "private", "selected"})
VALID_SCOPE_KINDS = frozenset({"repository", "environment", "organization"})
SCOPE_KIND_MESSAGE = "Invalid GitHub scope; require kind repository|environment|organization"


@dataclass(frozen=True, slots=True)
class GitHubRepoRef:
    """Resolved GitHub owner + optional repository name."""

    owner: str
    repository: str | None = None


@dataclass(frozen=True, slots=True)
class _ConfigParseError:
    message: str
    hint: str | None = None


def _capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=True,
        read_values=False,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(supported=False),
        delete_batch=BatchCapability(supported=True, max_items=1),
        multiple_scopes_per_mutation=False,
        batch_across_scopes=False,
    )


def encrypt_github_secret(public_key_b64: str, secret_value: bytes) -> str:
    """LibSodium sealed-box encryption for GitHub Actions secrets API."""
    public_key = public.PublicKey(public_key_b64.encode("utf-8"), encoding.Base64Encoder)
    sealed = public.SealedBox(public_key).encrypt(secret_value)
    return base64.b64encode(sealed).decode("utf-8")


def _parse_github_target(
    config: Mapping[str, JsonValue],
) -> GitHubRepoRef | _ConfigParseError:
    """Resolve destination organization/repository into an owner (+ optional repo).

    Allowed:
      - organization: org
      - organization: org + repository: name  (name must not contain '/')
      - repository: owner/name               (no organization field)

    Rejected:
      - organization + repository: owner/name (redundant or mismatched)
      - repository: name without organization
      - neither field set
    """
    raw_org = config.get("organization")
    raw_repo = config.get("repository")

    org: str | None = None
    if raw_org is not None:
        if not isinstance(raw_org, str) or not raw_org.strip():
            return _ConfigParseError(
                message="github-actions organization must be a non-empty string",
                hint="Example: organization: my-org",
            )
        org = raw_org.strip()
        if not SEGMENT_RE.match(org):
            return _ConfigParseError(
                message=(
                    f"github-actions organization {org!r} must be a single path segment (no '/')"
                ),
                hint="Use organization: my-org — not an owner/repo string.",
            )

    repo: str | None = None
    if raw_repo is not None:
        if not isinstance(raw_repo, str) or not raw_repo.strip():
            return _ConfigParseError(
                message="github-actions repository must be a non-empty string",
                hint="Use repository: owner/name, or organization: + repository: name.",
            )
        repo = raw_repo.strip()

    if org is None and repo is None:
        return _ConfigParseError(
            message="github-actions requires organization and/or repository",
            hint=(
                "Set organization: my-org, or repository: owner/name, "
                "or both as organization: my-org and repository: my-repo."
            ),
        )

    if org is not None and repo is None:
        return GitHubRepoRef(owner=org, repository=None)

    assert repo is not None

    if org is not None:
        if "/" in repo:
            if OWNER_REPO_RE.match(repo):
                owner, _name = repo.split("/", 1)
                if owner == org:
                    return _ConfigParseError(
                        message=(
                            "github-actions must not set organization together with "
                            "repository as 'owner/name'"
                        ),
                        hint=(
                            f"Use repository: {_name!r} with organization: {org!r}, "
                            f"or drop organization and keep repository: {repo!r}."
                        ),
                    )
                return _ConfigParseError(
                    message=(
                        f"github-actions organization {org!r} does not match "
                        f"repository owner {owner!r} in {repo!r}"
                    ),
                    hint=(
                        f"Use organization: {owner!r} with repository: "
                        f"{repo.split('/', 1)[1]!r}, or repository: {repo!r} alone."
                    ),
                )
            return _ConfigParseError(
                message=f"github-actions repository {repo!r} is invalid",
                hint="With organization set, repository must be a bare repo name (no '/').",
            )
        if not SEGMENT_RE.match(repo):
            return _ConfigParseError(
                message=f"github-actions repository {repo!r} is invalid",
                hint="With organization set, repository must be a bare repo name (no '/').",
            )
        return GitHubRepoRef(owner=org, repository=repo)

    # repository alone — must be owner/name
    if not OWNER_REPO_RE.match(repo):
        return _ConfigParseError(
            message=(
                f"github-actions repository {repo!r} must be 'owner/name' "
                "when organization is omitted"
            ),
            hint=("Use repository: owner/name, or set organization: owner and repository: name."),
        )
    owner, name = repo.split("/", 1)
    return GitHubRepoRef(owner=owner, repository=name)


def _parse_repository(config: Mapping[str, JsonValue]) -> tuple[str, str] | None:
    """Return (owner, repo) when the destination resolves to a concrete repository."""
    parsed = _parse_github_target(config)
    if isinstance(parsed, _ConfigParseError) or parsed.repository is None:
        return None
    return parsed.owner, parsed.repository


def _require_repo_ref(
    config: Mapping[str, JsonValue],
) -> tuple[str, str] | _ConfigParseError:
    """Like _parse_github_target, but require a concrete repository for repo/env ops."""
    parsed = _parse_github_target(config)
    if isinstance(parsed, _ConfigParseError):
        return parsed
    return _owner_repo_for_scope(parsed, {"kind": "repository"})


def _owner_repo_for_scope(
    parsed: GitHubRepoRef,
    scope: Mapping[str, JsonValue],
) -> tuple[str, str] | _ConfigParseError:
    """Resolve owner/repo for a scope. Organization scope needs owner only."""
    if scope.get("kind") == "organization":
        return parsed.owner, parsed.repository or ""
    if parsed.repository is None:
        return _ConfigParseError(
            message=(
                f"github-actions destination has organization {parsed.owner!r} "
                "but no repository; repository/environment scopes require a repository"
            ),
            hint=(
                f"Add repository: <repo-name> under the destination, or use "
                f"repository: {parsed.owner}/<repo-name>."
            ),
        )
    return parsed.owner, parsed.repository


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
    if kind == "organization":
        visibility = scope.get("visibility", "private")
        ids = scope.get("selectedRepositoryIds")
        if visibility == "selected" and isinstance(ids, list):
            return f"organization:{visibility}:{','.join(str(i) for i in ids)}"
        return f"organization:{visibility}"
    return "repository"


def _public_key_cache_key(scope: Mapping[str, JsonValue]) -> str:
    # ponytail: one org public key shared across visibility variants
    if scope.get("kind") == "organization":
        return "organization"
    return _scope_key(scope)


def _org_visibility_error(scope: Mapping[str, JsonValue]) -> str | None:
    """Validate organization visibility / selectedRepositoryIds; None if ok."""
    if "visibility" not in scope:
        return "organization scope requires visibility; require all|private|selected"
    visibility = scope.get("visibility")
    if visibility not in ORG_VISIBILITIES:
        return "Invalid organization visibility; require all|private|selected"
    if visibility == "selected":
        ids = scope.get("selectedRepositoryIds")
        # bool is a subclass of int; reject it explicitly.
        valid_ids = (
            isinstance(ids, list)
            and bool(ids)
            and all(isinstance(i, int) and not isinstance(i, bool) for i in ids)
        )
        if not valid_ids:
            return (
                "selectedRepositoryIds required as non-empty int array when visibility is selected"
            )
    return None


def _org_visibility_payload(scope: Mapping[str, JsonValue]) -> dict[str, JsonValue] | str:
    """Return visibility fields for org create/update, or an error message."""
    # Apply keeps a private default for callers that skip offline validate.
    if "visibility" not in scope:
        scope = {**scope, "visibility": "private"}
    err = _org_visibility_error(scope)
    if err is not None:
        return err
    visibility = str(scope["visibility"])
    payload: dict[str, JsonValue] = {"visibility": visibility}
    if visibility == "selected":
        ids = scope["selectedRepositoryIds"]
        assert isinstance(ids, list)  # narrowed by _org_visibility_error
        # GitHub Actions API field name is snake_case.
        payload["selected_repository_ids"] = list(ids)
    return payload


def _invalid_scope_kind(scope: Mapping[str, JsonValue]) -> str | None:
    kind = scope.get("kind")
    if kind == "environment" and not scope.get("environment"):
        return "Invalid GitHub scope; environment name required"
    if kind not in VALID_SCOPE_KINDS:
        return SCOPE_KIND_MESSAGE
    return None


def _validate_scope(scope: Mapping[str, JsonValue]) -> str | None:
    """Offline / preflight scope checks. Return error message or None."""
    kind_err = _invalid_scope_kind(scope)
    if kind_err is not None:
        return kind_err
    if scope.get("kind") == "organization":
        return _org_visibility_error(scope)
    return None


@dataclass
class GitHubActionsDestination:
    manifest: DestinationManifest
    environ: Mapping[str, str]
    http_client_factory: Any
    put_concurrency: int = 4
    _public_keys: dict[str, tuple[str, str]] = field(default_factory=dict)

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        issues: list[Issue] = []
        parsed = _parse_github_target(config)
        if isinstance(parsed, _ConfigParseError):
            issues.append(
                Issue(
                    code="DESTINATION_INVALID",
                    message=parsed.message,
                    hint=parsed.hint,
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

    def check_kind_support(self, kind: ValueKind) -> Issue | None:
        del kind
        return None

    async def list_names(
        self,
        config: Mapping[str, JsonValue],
        scope: Mapping[str, JsonValue],
        context: OperationContext,
        *,
        kind: ValueKind = ValueKind.SECRET,
    ) -> frozenset[str]:
        parsed = _parse_github_target(config)
        token_env = _token_env(config)
        if isinstance(parsed, _ConfigParseError) or token_env is None:
            message = (
                parsed.message
                if isinstance(parsed, _ConfigParseError)
                else "Invalid github-actions destination configuration"
            )
            hint = parsed.hint if isinstance(parsed, _ConfigParseError) else None
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=message,
                    hint=hint,
                    correlation_id=context.correlation_id,
                )
            )
        token = self.environ.get(token_env)
        if not token:
            raise ListNamesError(
                SafeConnectorError(
                    code="AUTH_MISSING",
                    message=f"Connector credential environment variable '{token_env}' is absent",
                    correlation_id=context.correlation_id,
                )
            )
        scope_error = _invalid_scope_kind(scope)
        if scope_error is not None:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=scope_error,
                    correlation_id=context.correlation_id,
                )
            )
        resolved = _owner_repo_for_scope(parsed, scope)
        if isinstance(resolved, _ConfigParseError):
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=resolved.message,
                    hint=resolved.hint,
                    correlation_id=context.correlation_id,
                )
            )

        owner, repo = resolved
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        client = self.http_client_factory.create(headers=headers)
        collection_key = "secrets" if kind is ValueKind.SECRET else "variables"
        names: set[str] = set()
        try:
            async with client:
                page = 1
                while True:
                    url = (
                        _secrets_collection_url(owner, repo, scope)
                        if kind is ValueKind.SECRET
                        else _variables_collection_url(owner, repo, scope)
                    )
                    response = await request_with_retries(
                        client,
                        "GET",
                        url,
                        params={"per_page": "100", "page": str(page)},
                        correlation_id=context.correlation_id,
                    )
                    if response.status_code != 200:
                        from secretsync.infrastructure.http import error_for_status

                        raise ListNamesError(
                            error_for_status(response, correlation_id=context.correlation_id)
                        )
                    payload = response.json()
                    items = payload.get(collection_key, []) if isinstance(payload, dict) else []
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict) and "name" in item:
                                names.add(str(item["name"]))
                    if not isinstance(items, list) or len(items) < 100:
                        break
                    page += 1
        except HttpRequestError as exc:
            raise ListNamesError(exc.safe) from exc
        return frozenset(names)

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        config = request.destination_config
        parsed = _parse_github_target(config)
        token_env = _token_env(config)
        all_ids = [m.mutation_id for m in request.mutations] + [
            d.mutation_id for d in request.deletes
        ]
        if isinstance(parsed, _ConfigParseError) or token_env is None:
            error = SafeConnectorError(
                code="DESTINATION_INVALID",
                message=(
                    parsed.message
                    if isinstance(parsed, _ConfigParseError)
                    else "Invalid github-actions destination configuration"
                ),
                hint=parsed.hint if isinstance(parsed, _ConfigParseError) else None,
                correlation_id=context.correlation_id,
            )
            return ApplyDestinationResult(
                results=tuple(MutationResult(mid, "failed", None, error) for mid in all_ids),
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
                results=tuple(MutationResult(mid, "failed", None, error) for mid in all_ids),
                requests_made=0,
            )

        secret_mutations = [m for m in request.mutations if m.kind is ValueKind.SECRET]
        variable_mutations = [m for m in request.mutations if m.kind is ValueKind.VARIABLE]

        # Group secrets by scope for public-key caching; still one PUT per mutation.
        by_scope: dict[str, list[PutMutation]] = {}
        for mutation in secret_mutations:
            if not mutation.scopes:
                by_scope.setdefault("invalid", []).append(mutation)
                continue
            scope = dict(mutation.scopes[0])
            if _invalid_scope_kind(scope) is not None:
                by_scope.setdefault("invalid", []).append(mutation)
            else:
                by_scope.setdefault(_scope_key(scope), []).append(mutation)

        results: dict[str, MutationResult] = {}
        requests_made = 0

        for mutation in by_scope.get("invalid", []):
            results[mutation.mutation_id] = MutationResult(
                mutation_id=mutation.mutation_id,
                status="failed",
                error=SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=SCOPE_KIND_MESSAGE,
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
        async with client:
            for scope_id, mutations in by_scope.items():
                if scope_id == "invalid":
                    continue
                scope = dict(mutations[0].scopes[0])
                resolved = _owner_repo_for_scope(parsed, scope)
                if isinstance(resolved, _ConfigParseError):
                    for mutation in mutations:
                        results[mutation.mutation_id] = MutationResult(
                            mutation_id=mutation.mutation_id,
                            status="failed",
                            error=SafeConnectorError(
                                code="DESTINATION_INVALID",
                                message=resolved.message,
                                hint=resolved.hint,
                                mutation_id=mutation.mutation_id,
                                correlation_id=context.correlation_id,
                            ),
                        )
                    continue
                owner, repo = resolved
                if scope.get("kind") == "organization":
                    visibility = _org_visibility_payload(scope)
                    if isinstance(visibility, str):
                        for mutation in mutations:
                            results[mutation.mutation_id] = MutationResult(
                                mutation_id=mutation.mutation_id,
                                status="failed",
                                error=SafeConnectorError(
                                    code="DESTINATION_INVALID",
                                    message=visibility,
                                    mutation_id=mutation.mutation_id,
                                    correlation_id=context.correlation_id,
                                ),
                            )
                        continue
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
                    put_owner: str,
                    put_repo: str,
                    put_key_id: str,
                    put_key_b64: str,
                ) -> None:
                    nonlocal requests_made
                    async with limiter:
                        result, n = await self._put_secret(
                            client,
                            put_owner,
                            put_repo,
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
                        tg.start_soon(
                            put_one,
                            mutation,
                            dict(mutation.scopes[0]),
                            owner,
                            repo,
                            key_id,
                            key_b64,
                        )

            async def put_variable(mutation: PutMutation) -> None:
                nonlocal requests_made
                async with limiter:
                    if not mutation.scopes:
                        results[mutation.mutation_id] = MutationResult(
                            mutation_id=mutation.mutation_id,
                            status="failed",
                            error=SafeConnectorError(
                                code="DESTINATION_INVALID",
                                message="Missing GitHub scope on mutation",
                                mutation_id=mutation.mutation_id,
                                correlation_id=context.correlation_id,
                            ),
                        )
                        return
                    resolved = _owner_repo_for_scope(parsed, dict(mutation.scopes[0]))
                    if isinstance(resolved, _ConfigParseError):
                        results[mutation.mutation_id] = MutationResult(
                            mutation_id=mutation.mutation_id,
                            status="failed",
                            error=SafeConnectorError(
                                code="DESTINATION_INVALID",
                                message=resolved.message,
                                hint=resolved.hint,
                                mutation_id=mutation.mutation_id,
                                correlation_id=context.correlation_id,
                            ),
                        )
                        return
                    var_owner, var_repo = resolved
                    result, n = await self._put_variable(
                        client, var_owner, var_repo, mutation, context.correlation_id
                    )
                    results[mutation.mutation_id] = result
                    requests_made += n

            async with anyio.create_task_group() as tg:
                for mutation in variable_mutations:
                    tg.start_soon(put_variable, mutation)

            for deletion in request.deletes:
                if not deletion.scopes:
                    results[deletion.mutation_id] = MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message="Missing GitHub scope on delete",
                            mutation_id=deletion.mutation_id,
                            correlation_id=context.correlation_id,
                        ),
                    )
                    continue
                resolved = _owner_repo_for_scope(parsed, dict(deletion.scopes[0]))
                if isinstance(resolved, _ConfigParseError):
                    results[deletion.mutation_id] = MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=resolved.message,
                            hint=resolved.hint,
                            mutation_id=deletion.mutation_id,
                            correlation_id=context.correlation_id,
                        ),
                    )
                    continue
                del_owner, del_repo = resolved
                if deletion.kind is ValueKind.VARIABLE:
                    result, n = await self._delete_variable(
                        client, del_owner, del_repo, deletion, context.correlation_id
                    )
                else:
                    result, n = await self._delete_secret(
                        client, del_owner, del_repo, deletion, context.correlation_id
                    )
                results[deletion.mutation_id] = result
                requests_made += n

        ordered = tuple(
            results.get(
                mid,
                MutationResult(
                    mutation_id=mid,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Connector omitted result for mutation",
                        mutation_id=mid,
                        correlation_id=context.correlation_id,
                    ),
                ),
            )
            for mid in all_ids
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
        cache_key = _public_key_cache_key(scope)
        if cache_key in self._public_keys:
            key_id, key_b64 = self._public_keys[cache_key]
            return key_id, key_b64, 0

        kind = scope.get("kind")
        if kind == "organization":
            url = f"{GITHUB_API}/orgs/{owner}/actions/secrets/public-key"
        elif kind == "environment":
            env_name = quote(str(scope["environment"]), safe="")
            url = f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/public-key"
        else:
            url = f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets/public-key"

        response = await request_with_retries(client, "GET", url, correlation_id=correlation_id)
        if response.status_code != 200:
            from secretsync.infrastructure.http import error_for_status

            raise HttpRequestError(error_for_status(response, correlation_id=correlation_id))
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

        body: dict[str, JsonValue] = {}
        if scope.get("kind") == "organization":
            visibility = _org_visibility_payload(scope)
            if isinstance(visibility, str):
                return (
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=visibility,
                            mutation_id=mutation.mutation_id,
                            correlation_id=correlation_id,
                        ),
                    ),
                    0,
                )
            body.update(visibility)

        ciphertext = bytearray()
        try:
            encrypted = encrypt_github_secret(key_b64, bytes(mutation.value))
            ciphertext.extend(encrypted.encode("utf-8"))
            body["encrypted_value"] = encrypted
            body["key_id"] = key_id
            url = _secret_item_url(owner, repo, scope, mutation.name)

            response = await request_with_retries(
                client,
                "PUT",
                url,
                mutation_id=mutation.mutation_id,
                correlation_id=correlation_id,
                json=body,
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
                        response,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                        secrets=[bytes(mutation.value).decode("utf-8", errors="replace")],
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

    async def _put_variable(
        self,
        client: Any,
        owner: str,
        repo: str,
        mutation: PutMutation,
        correlation_id: str,
    ) -> tuple[MutationResult, int]:
        if not mutation.scopes:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing GitHub scope on mutation",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        scope = dict(mutation.scopes[0])
        scope_error = _invalid_scope_kind(scope)
        if scope_error is not None:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=scope_error,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        if not VARIABLE_NAME_RE.match(mutation.name):
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=f"Invalid GitHub variable name '{mutation.name}'",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )

        value = bytes(mutation.value).decode("utf-8")
        body: dict[str, JsonValue] = {"name": mutation.name, "value": value}
        if scope.get("kind") == "organization":
            visibility = _org_visibility_payload(scope)
            if isinstance(visibility, str):
                return (
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=visibility,
                            mutation_id=mutation.mutation_id,
                            correlation_id=correlation_id,
                        ),
                    ),
                    0,
                )
            body.update(visibility)

        collection = _variables_collection_url(owner, repo, scope)
        item = _variable_item_url(owner, repo, scope, mutation.name)
        try:
            create = await request_with_retries(
                client,
                "POST",
                collection,
                mutation_id=mutation.mutation_id,
                correlation_id=correlation_id,
                json=body,
            )
            if create.status_code == 201:
                return (
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="applied",
                        effect="created",
                    ),
                    1,
                )
            if create.status_code in {409, 422}:
                update = await request_with_retries(
                    client,
                    "PATCH",
                    item,
                    mutation_id=mutation.mutation_id,
                    correlation_id=correlation_id,
                    json=body,
                )
                if update.status_code in {200, 204}:
                    return (
                        MutationResult(
                            mutation_id=mutation.mutation_id,
                            status="applied",
                            effect="updated",
                        ),
                        2,
                    )
                from secretsync.infrastructure.http import error_for_status

                return (
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="failed",
                        error=error_for_status(
                            update,
                            mutation_id=mutation.mutation_id,
                            correlation_id=correlation_id,
                            secrets=[bytes(mutation.value).decode("utf-8", errors="replace")],
                        ),
                    ),
                    2,
                )
            from secretsync.infrastructure.http import error_for_status

            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=error_for_status(
                        create,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                        secrets=[bytes(mutation.value).decode("utf-8", errors="replace")],
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

    async def _delete_variable(
        self,
        client: Any,
        owner: str,
        repo: str,
        deletion: DeleteMutation,
        correlation_id: str,
    ) -> tuple[MutationResult, int]:
        if not deletion.scopes:
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing GitHub scope on delete",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        scope = dict(deletion.scopes[0])
        scope_error = _invalid_scope_kind(scope)
        if scope_error is not None:
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=scope_error,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        if not VARIABLE_NAME_RE.match(deletion.name):
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=f"Invalid GitHub variable name '{deletion.name}'",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        url = _variable_item_url(owner, repo, scope, deletion.name)
        try:
            response = await request_with_retries(
                client,
                "DELETE",
                url,
                mutation_id=deletion.mutation_id,
                correlation_id=correlation_id,
            )
            if response.status_code in {204, 404}:
                return (
                    MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="applied",
                        effect="deleted",
                    ),
                    1,
                )
            from secretsync.infrastructure.http import error_for_status

            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=error_for_status(
                        response,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                1,
            )
        except HttpRequestError as exc:
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=exc.safe,
                ),
                1,
            )

    async def _delete_secret(
        self,
        client: Any,
        owner: str,
        repo: str,
        deletion: DeleteMutation,
        correlation_id: str,
    ) -> tuple[MutationResult, int]:
        if not deletion.scopes:
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing GitHub scope on delete",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        scope = dict(deletion.scopes[0])
        scope_error = _invalid_scope_kind(scope)
        if scope_error is not None:
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=scope_error,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        if not SECRET_NAME_RE.match(deletion.name):
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=f"Invalid GitHub secret name '{deletion.name}'",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        url = _secret_item_url(owner, repo, scope, deletion.name)
        try:
            response = await request_with_retries(
                client,
                "DELETE",
                url,
                mutation_id=deletion.mutation_id,
                correlation_id=correlation_id,
            )
            if response.status_code in {204, 404}:
                return (
                    MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="applied",
                        effect="deleted",
                    ),
                    1,
                )
            from secretsync.infrastructure.http import error_for_status

            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=error_for_status(
                        response,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                1,
            )
        except HttpRequestError as exc:
            return (
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=exc.safe,
                ),
                1,
            )


def _secrets_collection_url(owner: str, repo: str, scope: Mapping[str, JsonValue]) -> str:
    kind = scope.get("kind")
    if kind == "organization":
        return f"{GITHUB_API}/orgs/{owner}/actions/secrets"
    if kind == "environment":
        env_name = quote(str(scope["environment"]), safe="")
        return f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets"
    return f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets"


def _secret_item_url(owner: str, repo: str, scope: Mapping[str, JsonValue], name: str) -> str:
    kind = scope.get("kind")
    if kind == "organization":
        return f"{GITHUB_API}/orgs/{owner}/actions/secrets/{name}"
    if kind == "environment":
        env_name = quote(str(scope["environment"]), safe="")
        return f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/secrets/{name}"
    return f"{GITHUB_API}/repos/{owner}/{repo}/actions/secrets/{name}"


def _variables_collection_url(owner: str, repo: str, scope: Mapping[str, JsonValue]) -> str:
    kind = scope.get("kind")
    if kind == "organization":
        return f"{GITHUB_API}/orgs/{owner}/actions/variables"
    if kind == "environment":
        env_name = quote(str(scope["environment"]), safe="")
        return f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables"
    return f"{GITHUB_API}/repos/{owner}/{repo}/actions/variables"


def _variable_item_url(owner: str, repo: str, scope: Mapping[str, JsonValue], name: str) -> str:
    kind = scope.get("kind")
    if kind == "organization":
        return f"{GITHUB_API}/orgs/{owner}/actions/variables/{name}"
    if kind == "environment":
        env_name = quote(str(scope["environment"]), safe="")
        return f"{GITHUB_API}/repos/{owner}/{repo}/environments/{env_name}/variables/{name}"
    return f"{GITHUB_API}/repos/{owner}/{repo}/actions/variables/{name}"


@dataclass(frozen=True, slots=True)
class GitHubActionsFactory:
    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="github-actions",
            version="0.3.0+org-secrets-variables",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> GitHubActionsDestination:
        return GitHubActionsDestination(
            manifest=self.manifest,
            environ=services.environ,
            http_client_factory=services.http_client_factory,
        )
