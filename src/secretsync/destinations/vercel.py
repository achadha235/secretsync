"""Vercel project and shared environment variables destination."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

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
from secretsync.infrastructure.http import HttpRequestError, error_for_status, request_with_retries

VERCEL_API = "https://api.vercel.com"
API_PATH = "/v10/projects/{project}/env"
SHARED_ENV_PATH = "/v1/env"
DEFAULT_MAX_ITEMS = 100
SHARED_MAX_ITEMS = 50
SENSITIVE_TARGETS = frozenset({"production", "preview"})
SCOPE_KIND_ENVIRONMENT = "environment"
SCOPE_KIND_SHARED = "shared-environment"
VALID_SCOPE_KINDS = frozenset({SCOPE_KIND_ENVIRONMENT, SCOPE_KIND_SHARED})


def _capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=True,
        read_values=True,  # conditional; sensitive values non-readable
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(
            supported=True,
            max_items=DEFAULT_MAX_ITEMS,
            atomic=False,
            transport="api",
        ),
        delete_batch=BatchCapability(supported=True),
        multiple_scopes_per_mutation=True,
        batch_across_scopes=True,
    )


def _token_env(config: Mapping[str, JsonValue]) -> str | None:
    auth = config.get("auth")
    if isinstance(auth, dict):
        token_env = auth.get("tokenEnv")
        if isinstance(token_env, str) and token_env:
            return token_env
    return None


def _project(config: Mapping[str, JsonValue]) -> str | None:
    project = config.get("project")
    return project if isinstance(project, str) and project else None


def _team_id(config: Mapping[str, JsonValue]) -> str | None:
    team = config.get("teamId")
    return team if isinstance(team, str) and team else None


def _scope_kind(scope: Mapping[str, JsonValue]) -> str | None:
    kind = scope.get("kind")
    return kind if isinstance(kind, str) and kind else None


def _scope_projects(scope: Mapping[str, JsonValue]) -> frozenset[str]:
    projects = scope.get("projects")
    if not isinstance(projects, list):
        return frozenset()
    return frozenset(str(p) for p in projects if isinstance(p, str) and p)


def _remote_projects(item: Mapping[str, Any]) -> frozenset[str]:
    raw = item.get("projectId")
    if not isinstance(raw, list):
        return frozenset()
    return frozenset(str(p) for p in raw if p)


def _validate_scope(
    scope: Mapping[str, JsonValue],
    *,
    kind: ValueKind = ValueKind.SECRET,
    destination_project: str | None = None,
) -> str | None:
    scope_kind = _scope_kind(scope)
    if scope_kind not in VALID_SCOPE_KINDS:
        return (
            "scope.kind must be 'environment' or 'shared-environment' "
            "(add kind: environment for project env deployments)"
        )

    targets = scope.get("targets")
    if not isinstance(targets, list) or not targets or not all(isinstance(t, str) for t in targets):
        return "scope.targets must be a non-empty string array"
    if "sensitive" in scope:
        return (
            "scope.sensitive is no longer supported; remove it and use deployment.secrets "
            "vs deployment.variables so the connector sets type from kind"
        )
    if kind is ValueKind.SECRET:
        illegal = [t for t in targets if t not in SENSITIVE_TARGETS]
        if illegal:
            return "sensitive (secret) variables are limited to production and preview targets"

    git_branch = scope.get("gitBranch")
    projects = scope.get("projects")

    if scope_kind == SCOPE_KIND_ENVIRONMENT:
        if not destination_project:
            return "destination.project is required for scope.kind=environment"
        if projects is not None:
            return "scope.projects is only valid for scope.kind=shared-environment"
        if git_branch is not None:
            if not isinstance(git_branch, str):
                return "scope.gitBranch must be a string"
            if "preview" not in targets:
                return "scope.gitBranch is only valid with preview target"
        return None

    # shared-environment
    if git_branch is not None:
        return "scope.gitBranch is not supported for scope.kind=shared-environment"
    if projects is not None and (
        not isinstance(projects, list)
        or not projects
        or not all(isinstance(p, str) and p for p in projects)
    ):
        return "scope.projects must be a non-empty array of non-empty strings"
    return None


def _env_type(kind: ValueKind) -> str:
    if kind is ValueKind.SECRET:
        return "sensitive"
    return "encrypted"


def _targets_and_type_match(
    item: Mapping[str, Any],
    scope: Mapping[str, JsonValue],
    *,
    kind: ValueKind,
) -> bool:
    """True when remote target set equals scope.targets (exact ownership).

    Overlap matching is wrong: a shared deployment with targets [production, preview]
    must not own (list/update/prune) rows that only target production or only preview.
    """
    targets_raw = scope.get("targets")
    if not isinstance(targets_raw, list):
        return False
    wanted = {str(t) for t in targets_raw}
    remote_targets = item.get("target") or item.get("targets") or []
    if not isinstance(remote_targets, list):
        return False
    remote = {str(t) for t in remote_targets}
    if wanted != remote:
        return False
    remote_type = str(item.get("type", ""))
    if kind is ValueKind.SECRET:
        return remote_type == "sensitive"
    return remote_type != "sensitive"


def _env_matches_scope(
    item: Mapping[str, Any],
    scope: Mapping[str, JsonValue],
    *,
    kind: ValueKind = ValueKind.SECRET,
) -> bool:
    """True when a remote env entry belongs to the deployment inventory unit."""
    if not _targets_and_type_match(item, scope, kind=kind):
        return False

    scope_kind = _scope_kind(scope)
    if scope_kind == SCOPE_KIND_SHARED:
        return _remote_projects(item) == _scope_projects(scope)

    scope_branch = scope.get("gitBranch")
    item_branch = item.get("gitBranch")
    if scope_branch is None:
        if item_branch is not None:
            return False
    elif item_branch != scope_branch:
        return False
    return True


def _parse_env_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        envs = payload.get("envs", [])
        if isinstance(envs, list):
            return [item for item in envs if isinstance(item, dict)]
    return []


def _parse_shared_env_page(payload: Any) -> tuple[list[dict[str, Any]], Any]:
    if not isinstance(payload, dict):
        return [], None
    data = payload.get("data", [])
    items = [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []
    pagination = payload.get("pagination")
    next_ts = None
    if isinstance(pagination, dict):
        next_ts = pagination.get("next")
    return items, next_ts


@dataclass
class VercelDestination:
    manifest: DestinationManifest
    environ: Mapping[str, str]
    http_client_factory: Any

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        issues: list[Issue] = []
        if _team_id(config) is None:
            issues.append(
                Issue(
                    code="DESTINATION_INVALID",
                    message="vercel requires teamId",
                    hint="Set destinations.<name>.teamId to your Vercel team id (team_…)",
                )
            )
        if _token_env(config) is None:
            issues.append(Issue(code="AUTH_MISSING", message="vercel requires auth.tokenEnv"))
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
        team_id = _team_id(config)
        token_env = _token_env(config)
        if team_id is None or token_env is None:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Invalid vercel destination configuration",
                    correlation_id=context.correlation_id,
                )
            )
        project = _project(config)
        reason = _validate_scope(dict(scope), kind=kind, destination_project=project)
        if reason:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=reason,
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
        headers = {"Authorization": f"Bearer {token}"}
        client = self.http_client_factory.create(headers=headers)
        scope_kind = _scope_kind(scope)
        try:
            async with client:
                if scope_kind == SCOPE_KIND_SHARED:
                    envs, _ = await self._list_shared_envs(
                        client, team_id=team_id, correlation_id=context.correlation_id
                    )
                else:
                    assert project is not None
                    envs, _ = await self._list_envs(
                        client,
                        project=project,
                        team_id=team_id,
                        correlation_id=context.correlation_id,
                    )
        except HttpRequestError as exc:
            raise ListNamesError(exc.safe) from exc
        except ListNamesError:
            raise
        names = {
            str(item["key"])
            for item in envs
            if "key" in item and _env_matches_scope(item, scope, kind=kind)
        }
        return frozenset(names)

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        config = request.destination_config
        team_id = _team_id(config)
        token_env = _token_env(config)
        project = _project(config)
        all_ops: list[PutMutation | DeleteMutation] = [*request.mutations, *request.deletes]
        if team_id is None or token_env is None:
            error = SafeConnectorError(
                code="DESTINATION_INVALID",
                message="Invalid vercel destination configuration",
                correlation_id=context.correlation_id,
            )
            return _all_failed_ops(all_ops, error)

        token = self.environ.get(token_env)
        if not token:
            error = SafeConnectorError(
                code="AUTH_MISSING",
                message=f"Connector credential environment variable '{token_env}' is absent",
                correlation_id=context.correlation_id,
            )
            return _all_failed_ops(all_ops, error)

        for mutation in request.mutations:
            if not mutation.scopes:
                error = SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Missing Vercel scope on mutation",
                    mutation_id=mutation.mutation_id,
                    correlation_id=context.correlation_id,
                )
                return _all_failed_ops(all_ops, error)
            reason = _validate_scope(
                dict(mutation.scopes[0]),
                kind=mutation.kind,
                destination_project=project,
            )
            if reason:
                error = SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=reason,
                    mutation_id=mutation.mutation_id,
                    correlation_id=context.correlation_id,
                )
                return _all_failed_ops(all_ops, error)
        for deletion in request.deletes:
            if not deletion.scopes:
                error = SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Missing Vercel scope on delete",
                    mutation_id=deletion.mutation_id,
                    correlation_id=context.correlation_id,
                )
                return _all_failed_ops(all_ops, error)
            reason = _validate_scope(
                dict(deletion.scopes[0]),
                kind=deletion.kind,
                destination_project=project,
            )
            if reason:
                error = SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=reason,
                    mutation_id=deletion.mutation_id,
                    correlation_id=context.correlation_id,
                )
                return _all_failed_ops(all_ops, error)

        env_puts = [
            m for m in request.mutations if _scope_kind(m.scopes[0]) == SCOPE_KIND_ENVIRONMENT
        ]
        shared_puts = [
            m for m in request.mutations if _scope_kind(m.scopes[0]) == SCOPE_KIND_SHARED
        ]
        env_deletes = [
            d for d in request.deletes if _scope_kind(d.scopes[0]) == SCOPE_KIND_ENVIRONMENT
        ]
        shared_deletes = [
            d for d in request.deletes if _scope_kind(d.scopes[0]) == SCOPE_KIND_SHARED
        ]

        headers = {"Authorization": f"Bearer {token}"}
        client = self.http_client_factory.create(headers=headers)
        max_items = self.manifest.capabilities.put_batch.max_items or DEFAULT_MAX_ITEMS
        requests_made = 0
        results: dict[str, MutationResult] = {}

        async with client:
            if env_puts or env_deletes:
                assert project is not None
                for chunk in _chunks(env_puts, max_items):
                    if not chunk:
                        continue
                    chunk_results, n = await self._upsert_chunk(
                        client,
                        project=project,
                        team_id=team_id,
                        mutations=chunk,
                        correlation_id=context.correlation_id,
                    )
                    requests_made += n
                    results.update(chunk_results)
                if env_deletes:
                    delete_results, n = await self._delete_many(
                        client,
                        project=project,
                        team_id=team_id,
                        deletes=env_deletes,
                        correlation_id=context.correlation_id,
                    )
                    requests_made += n
                    results.update(delete_results)

            if shared_puts:
                put_results, n = await self._upsert_shared(
                    client,
                    team_id=team_id,
                    mutations=shared_puts,
                    correlation_id=context.correlation_id,
                )
                requests_made += n
                results.update(put_results)
            if shared_deletes:
                delete_results, n = await self._delete_shared(
                    client,
                    team_id=team_id,
                    deletes=shared_deletes,
                    correlation_id=context.correlation_id,
                )
                requests_made += n
                results.update(delete_results)

        ordered = tuple(results[op.mutation_id] for op in all_ops)
        return ApplyDestinationResult(results=ordered, requests_made=requests_made)

    async def _upsert_chunk(
        self,
        client: Any,
        *,
        project: str,
        team_id: str,
        mutations: Sequence[PutMutation],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        payload = []
        for mutation in mutations:
            scope = dict(mutation.scopes[0])
            targets_raw = scope["targets"]
            assert isinstance(targets_raw, list)
            entry: dict[str, Any] = {
                "key": mutation.name,
                "value": bytes(mutation.value).decode("utf-8"),
                "type": _env_type(mutation.kind),
                "target": [str(t) for t in targets_raw],
            }
            if scope.get("gitBranch"):
                entry["gitBranch"] = scope["gitBranch"]
            payload.append(entry)

        params: dict[str, str] = {"upsert": "true", "teamId": team_id}
        url = f"{VERCEL_API}{API_PATH.format(project=quote(project, safe=''))}"

        try:
            response = await request_with_retries(
                client,
                "POST",
                url,
                params=params,
                json=payload,
                correlation_id=correlation_id,
            )
        except HttpRequestError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code=exc.safe.code,
                            message=exc.safe.message,
                            mutation_id=m.mutation_id,
                            correlation_id=correlation_id,
                            retryable=exc.safe.retryable,
                        ),
                    )
                    for m in mutations
                },
                1,
            )

        if response.status_code in {200, 201}:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="applied",
                        effect="upserted",
                    )
                    for m in mutations
                },
                1,
            )

        if response.status_code in {400, 409}:
            edited, n = await self._edit_fallback(
                client,
                project=project,
                team_id=team_id,
                mutations=mutations,
                correlation_id=correlation_id,
            )
            return edited, 1 + n

        err = error_for_status(
            response,
            correlation_id=correlation_id,
            secrets=[bytes(m.value).decode("utf-8", errors="replace") for m in mutations],
        )
        return (
            {
                m.mutation_id: MutationResult(
                    mutation_id=m.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code=err.code,
                        message=err.message,
                        mutation_id=m.mutation_id,
                        correlation_id=correlation_id,
                        retryable=err.retryable,
                    ),
                )
                for m in mutations
            },
            1,
        )

    async def _list_envs(
        self,
        client: Any,
        *,
        project: str,
        team_id: str,
        correlation_id: str,
    ) -> tuple[list[dict[str, Any]], int]:
        list_url = f"{VERCEL_API}/v9/projects/{quote(project, safe='')}/env"
        params: dict[str, str] = {"teamId": team_id}
        listed = await request_with_retries(
            client, "GET", list_url, params=params, correlation_id=correlation_id
        )
        if listed.status_code != 200:
            raise ListNamesError(error_for_status(listed, correlation_id=correlation_id))
        return _parse_env_list(listed.json()), 1

    async def _list_shared_envs(
        self,
        client: Any,
        *,
        team_id: str,
        correlation_id: str,
    ) -> tuple[list[dict[str, Any]], int]:
        url = f"{VERCEL_API}{SHARED_ENV_PATH}"
        items: list[dict[str, Any]] = []
        requests = 0
        until: Any = None
        for _ in range(100):
            params: dict[str, str] = {"teamId": team_id}
            if until is not None:
                params["until"] = str(until)
            listed = await request_with_retries(
                client, "GET", url, params=params, correlation_id=correlation_id
            )
            requests += 1
            if listed.status_code != 200:
                raise ListNamesError(error_for_status(listed, correlation_id=correlation_id))
            page, next_ts = _parse_shared_env_page(listed.json())
            items.extend(page)
            if next_ts is None:
                break
            until = next_ts
        return items, requests

    async def _upsert_shared(
        self,
        client: Any,
        *,
        team_id: str,
        mutations: Sequence[PutMutation],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        try:
            envs, list_requests = await self._list_shared_envs(
                client, team_id=team_id, correlation_id=correlation_id
            )
        except ListNamesError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for m in mutations
                },
                1,
            )
        except HttpRequestError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for m in mutations
                },
                1,
            )

        to_update: list[tuple[PutMutation, str]] = []
        to_create: list[PutMutation] = []
        for mutation in mutations:
            scope = dict(mutation.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") == mutation.name and _env_matches_scope(
                    item, scope, kind=mutation.kind
                ):
                    env_id = str(item.get("id", "")) or None
                    break
            if env_id:
                to_update.append((mutation, env_id))
            else:
                to_create.append(mutation)

        results: dict[str, MutationResult] = {}
        requests = list_requests

        for update_chunk in _chunks(to_update, SHARED_MAX_ITEMS):
            chunk_results, n = await self._patch_shared(
                client,
                team_id=team_id,
                updates=update_chunk,
                correlation_id=correlation_id,
            )
            requests += n
            results.update(chunk_results)

        # Create batches share type + target + projectId at the request level.
        groups: dict[tuple[str, tuple[str, ...], tuple[str, ...]], list[PutMutation]] = {}
        for mutation in to_create:
            scope = dict(mutation.scopes[0])
            targets_raw = scope["targets"]
            assert isinstance(targets_raw, list)
            targets = tuple(sorted(str(t) for t in targets_raw))
            projects = tuple(sorted(_scope_projects(scope)))
            key = (_env_type(mutation.kind), targets, projects)
            groups.setdefault(key, []).append(mutation)

        for (env_type, targets, projects), group in groups.items():
            for create_chunk in _chunks(group, SHARED_MAX_ITEMS):
                chunk_results, n = await self._create_shared(
                    client,
                    team_id=team_id,
                    mutations=create_chunk,
                    env_type=env_type,
                    targets=list(targets),
                    projects=list(projects),
                    correlation_id=correlation_id,
                )
                requests += n
                results.update(chunk_results)

        return results, requests

    async def _create_shared(
        self,
        client: Any,
        *,
        team_id: str,
        mutations: Sequence[PutMutation],
        env_type: str,
        targets: list[str],
        projects: list[str],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        body: dict[str, Any] = {
            "evs": [
                {
                    "key": m.name,
                    "value": bytes(m.value).decode("utf-8"),
                }
                for m in mutations
            ],
            "type": env_type,
            "target": targets,
        }
        if projects:
            body["projectId"] = projects
        url = f"{VERCEL_API}{SHARED_ENV_PATH}"
        params = {"teamId": team_id}
        try:
            response = await request_with_retries(
                client,
                "POST",
                url,
                params=params,
                json=body,
                correlation_id=correlation_id,
            )
        except HttpRequestError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code=exc.safe.code,
                            message=exc.safe.message,
                            mutation_id=m.mutation_id,
                            correlation_id=correlation_id,
                            retryable=exc.safe.retryable,
                        ),
                    )
                    for m in mutations
                },
                1,
            )
        if response.status_code in {200, 201}:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="applied",
                        effect="upserted",
                    )
                    for m in mutations
                },
                1,
            )
        err = error_for_status(
            response,
            correlation_id=correlation_id,
            secrets=[bytes(m.value).decode("utf-8", errors="replace") for m in mutations],
        )
        return (
            {
                m.mutation_id: MutationResult(
                    mutation_id=m.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code=err.code,
                        message=err.message,
                        mutation_id=m.mutation_id,
                        correlation_id=correlation_id,
                        retryable=err.retryable,
                    ),
                )
                for m in mutations
            },
            1,
        )

    async def _patch_shared(
        self,
        client: Any,
        *,
        team_id: str,
        updates: Sequence[tuple[PutMutation, str]],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        payload_updates: dict[str, Any] = {}
        for mutation, env_id in updates:
            scope = dict(mutation.scopes[0])
            targets_raw = scope["targets"]
            assert isinstance(targets_raw, list)
            entry: dict[str, Any] = {
                "value": bytes(mutation.value).decode("utf-8"),
                "type": _env_type(mutation.kind),
                "target": [str(t) for t in targets_raw],
            }
            projects = sorted(_scope_projects(scope))
            if projects:
                entry["projectId"] = projects
            payload_updates[env_id] = entry
        url = f"{VERCEL_API}{SHARED_ENV_PATH}"
        params = {"teamId": team_id}
        try:
            response = await request_with_retries(
                client,
                "PATCH",
                url,
                params=params,
                json={"updates": payload_updates},
                correlation_id=correlation_id,
            )
        except HttpRequestError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code=exc.safe.code,
                            message=exc.safe.message,
                            mutation_id=m.mutation_id,
                            correlation_id=correlation_id,
                            retryable=exc.safe.retryable,
                        ),
                    )
                    for m, _ in updates
                },
                1,
            )
        if response.status_code in {200, 201}:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="applied",
                        effect="updated",
                    )
                    for m, _ in updates
                },
                1,
            )
        err = error_for_status(
            response,
            correlation_id=correlation_id,
            secrets=[bytes(m.value).decode("utf-8", errors="replace") for m, _ in updates],
        )
        return (
            {
                m.mutation_id: MutationResult(
                    mutation_id=m.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code=err.code,
                        message=err.message,
                        mutation_id=m.mutation_id,
                        correlation_id=correlation_id,
                        retryable=err.retryable,
                    ),
                )
                for m, _ in updates
            },
            1,
        )

    async def _delete_shared(
        self,
        client: Any,
        *,
        team_id: str,
        deletes: Sequence[DeleteMutation],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        try:
            envs, list_requests = await self._list_shared_envs(
                client, team_id=team_id, correlation_id=correlation_id
            )
        except ListNamesError as exc:
            return (
                {
                    d.mutation_id: MutationResult(
                        mutation_id=d.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for d in deletes
                },
                1,
            )
        except HttpRequestError as exc:
            return (
                {
                    d.mutation_id: MutationResult(
                        mutation_id=d.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for d in deletes
                },
                1,
            )

        results: dict[str, MutationResult] = {}
        pending: list[tuple[DeleteMutation, str]] = []
        for deletion in deletes:
            scope = dict(deletion.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") == deletion.name and _env_matches_scope(
                    item, scope, kind=deletion.kind
                ):
                    env_id = str(item.get("id", "")) or None
                    break
            if env_id is None:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="applied",
                    effect="deleted",
                )
            else:
                pending.append((deletion, env_id))

        requests = list_requests
        url = f"{VERCEL_API}{SHARED_ENV_PATH}"
        params = {"teamId": team_id}
        for chunk in _chunks(pending, SHARED_MAX_ITEMS):
            ids = [env_id for _, env_id in chunk]
            try:
                response = await request_with_retries(
                    client,
                    "DELETE",
                    url,
                    params=params,
                    json={"ids": ids},
                    correlation_id=correlation_id,
                )
                requests += 1
            except HttpRequestError as exc:
                requests += 1
                for deletion, _ in chunk:
                    results[deletion.mutation_id] = MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                continue
            if response.status_code in {200, 204}:
                for deletion, _ in chunk:
                    results[deletion.mutation_id] = MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="applied",
                        effect="deleted",
                    )
            else:
                err = error_for_status(response, correlation_id=correlation_id)
                for deletion, _ in chunk:
                    results[deletion.mutation_id] = MutationResult(
                        mutation_id=deletion.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code=err.code,
                            message=err.message,
                            mutation_id=deletion.mutation_id,
                            correlation_id=correlation_id,
                            retryable=err.retryable,
                        ),
                    )
        return results, requests

    async def _delete_many(
        self,
        client: Any,
        *,
        project: str,
        team_id: str,
        deletes: Sequence[DeleteMutation],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        try:
            envs, list_requests = await self._list_envs(
                client, project=project, team_id=team_id, correlation_id=correlation_id
            )
        except ListNamesError as exc:
            return (
                {
                    d.mutation_id: MutationResult(
                        mutation_id=d.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for d in deletes
                },
                1,
            )
        except HttpRequestError as exc:
            return (
                {
                    d.mutation_id: MutationResult(
                        mutation_id=d.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for d in deletes
                },
                1,
            )

        results: dict[str, MutationResult] = {}
        requests = list_requests
        for deletion in deletes:
            scope = dict(deletion.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") == deletion.name and _env_matches_scope(
                    item, scope, kind=deletion.kind
                ):
                    env_id = str(item.get("id", "")) or None
                    break
            if env_id is None:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="applied",
                    effect="deleted",
                )
                continue
            delete_url = (
                f"{VERCEL_API}/v9/projects/{quote(project, safe='')}/env/{quote(env_id, safe='')}"
            )
            params: dict[str, str] = {"teamId": team_id}
            try:
                response = await request_with_retries(
                    client,
                    "DELETE",
                    delete_url,
                    params=params,
                    mutation_id=deletion.mutation_id,
                    correlation_id=correlation_id,
                )
                requests += 1
            except HttpRequestError as exc:
                requests += 1
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            if response.status_code in {200, 204, 404}:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="applied",
                    effect="deleted",
                )
            else:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=error_for_status(
                        response,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
        return results, requests

    async def _edit_fallback(
        self,
        client: Any,
        *,
        project: str,
        team_id: str,
        mutations: Sequence[PutMutation],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        """Retrieve env metadata and PATCH each conflicting key."""
        try:
            envs, list_requests = await self._list_envs(
                client, project=project, team_id=team_id, correlation_id=correlation_id
            )
        except ListNamesError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for m in mutations
                },
                1,
            )
        except HttpRequestError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=exc.safe,
                    )
                    for m in mutations
                },
                1,
            )

        by_key: dict[str, str] = {}
        for item in envs:
            if "key" not in item or "id" not in item:
                continue
            by_key[str(item["key"])] = str(item["id"])

        results: dict[str, MutationResult] = {}
        requests = list_requests
        for mutation in mutations:
            scope = dict(mutation.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") != mutation.name:
                    continue
                if _env_matches_scope(item, scope, kind=mutation.kind):
                    env_id = str(item.get("id", "")) or None
                    break
            if env_id is None:
                env_id = by_key.get(mutation.name)
            if env_id is None:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Conflict upsert failed and existing env id was not found",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            edit_url = (
                f"{VERCEL_API}/v9/projects/{quote(project, safe='')}/env/{quote(env_id, safe='')}"
            )
            targets_raw = scope["targets"]
            assert isinstance(targets_raw, list)
            body = {
                "value": bytes(mutation.value).decode("utf-8"),
                "type": _env_type(mutation.kind),
                "target": [str(t) for t in targets_raw],
            }
            edit_params: dict[str, str] = {"teamId": team_id}
            try:
                edited = await request_with_retries(
                    client,
                    "PATCH",
                    edit_url,
                    params=edit_params,
                    json=body,
                    mutation_id=mutation.mutation_id,
                    correlation_id=correlation_id,
                )
                requests += 1
            except HttpRequestError as exc:
                requests += 1
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            if edited.status_code in {200, 201}:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="applied",
                    effect="updated",
                )
            else:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=error_for_status(
                        edited,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                        secrets=[bytes(mutation.value).decode("utf-8", errors="replace")],
                    ),
                )
        return results, requests


def _chunks[T](items: Sequence[T], size: int) -> list[Sequence[T]]:
    if not items:
        return []
    return [items[i : i + size] for i in range(0, len(items), size)]


def _all_failed_ops(
    ops: Sequence[PutMutation | DeleteMutation], error: SafeConnectorError
) -> ApplyDestinationResult:
    return ApplyDestinationResult(
        results=tuple(
            MutationResult(mutation_id=op.mutation_id, status="failed", error=error) for op in ops
        ),
        requests_made=0,
    )


@dataclass(frozen=True, slots=True)
class VercelFactory:
    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="vercel",
            version="0.2.0+shared-env",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> VercelDestination:
        return VercelDestination(
            manifest=self.manifest,
            environ=services.environ,
            http_client_factory=services.http_client_factory,
        )
