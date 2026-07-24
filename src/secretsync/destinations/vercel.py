"""Vercel project environment variables destination (bulk upsert)."""

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
EDIT_PATH = "/v9/projects/{project}/env/{env_id}"
DEFAULT_MAX_ITEMS = 100
SENSITIVE_TARGETS = frozenset({"production", "preview"})


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


def _validate_scope(
    scope: Mapping[str, JsonValue],
    *,
    kind: ValueKind = ValueKind.SECRET,
) -> str | None:
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
    if git_branch is not None:
        if not isinstance(git_branch, str):
            return "scope.gitBranch must be a string"
        if "preview" not in targets:
            return "scope.gitBranch is only valid with preview target"
    return None


def _env_type(kind: ValueKind) -> str:
    if kind is ValueKind.SECRET:
        return "sensitive"
    return "encrypted"


def _env_matches_scope(
    item: Mapping[str, Any],
    scope: Mapping[str, JsonValue],
    *,
    kind: ValueKind = ValueKind.SECRET,
) -> bool:
    """True when a remote env entry belongs to the deployment inventory unit."""
    targets_raw = scope.get("targets")
    if not isinstance(targets_raw, list):
        return False
    wanted = {str(t) for t in targets_raw}
    remote_targets = item.get("target") or item.get("targets") or []
    if not isinstance(remote_targets, list):
        return False
    remote = {str(t) for t in remote_targets}
    if not wanted.intersection(remote):
        return False
    scope_branch = scope.get("gitBranch")
    item_branch = item.get("gitBranch")
    if scope_branch is None:
        if item_branch is not None:
            return False
    elif item_branch != scope_branch:
        return False
    remote_type = str(item.get("type", ""))
    if kind is ValueKind.SECRET:
        return remote_type == "sensitive"
    return remote_type != "sensitive"


def _parse_env_list(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        envs = payload.get("envs", [])
        if isinstance(envs, list):
            return [item for item in envs if isinstance(item, dict)]
    return []


@dataclass
class VercelDestination:
    manifest: DestinationManifest
    environ: Mapping[str, str]
    http_client_factory: Any

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        issues: list[Issue] = []
        if _project(config) is None:
            issues.append(Issue(code="DESTINATION_INVALID", message="vercel requires project"))
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
        project = _project(config)
        token_env = _token_env(config)
        if project is None or token_env is None:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Invalid vercel destination configuration",
                    correlation_id=context.correlation_id,
                )
            )
        reason = _validate_scope(dict(scope), kind=kind)
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
        team_id = _team_id(config)
        headers = {"Authorization": f"Bearer {token}"}
        client = self.http_client_factory.create(headers=headers)
        try:
            async with client:
                envs, _ = await self._list_envs(
                    client, project=project, team_id=team_id, correlation_id=context.correlation_id
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
        project = _project(config)
        token_env = _token_env(config)
        all_ops: list[PutMutation | DeleteMutation] = [*request.mutations, *request.deletes]
        if project is None or token_env is None:
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

        # Validate scopes up front.
        for mutation in request.mutations:
            if not mutation.scopes:
                error = SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Missing Vercel scope on mutation",
                    mutation_id=mutation.mutation_id,
                    correlation_id=context.correlation_id,
                )
                return _all_failed_ops(all_ops, error)
            reason = _validate_scope(dict(mutation.scopes[0]), kind=mutation.kind)
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
            reason = _validate_scope(dict(deletion.scopes[0]), kind=deletion.kind)
            if reason:
                error = SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=reason,
                    mutation_id=deletion.mutation_id,
                    correlation_id=context.correlation_id,
                )
                return _all_failed_ops(all_ops, error)

        team_id = _team_id(config)
        headers = {"Authorization": f"Bearer {token}"}
        client = self.http_client_factory.create(headers=headers)
        max_items = self.manifest.capabilities.put_batch.max_items or DEFAULT_MAX_ITEMS
        requests_made = 0
        results: dict[str, MutationResult] = {}

        async with client:
            for chunk in _chunks(request.mutations, max_items):
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

            if request.deletes:
                delete_results, n = await self._delete_many(
                    client,
                    project=project,
                    team_id=team_id,
                    deletes=request.deletes,
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
        team_id: str | None,
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

        params: dict[str, str] = {"upsert": "true"}
        if team_id:
            params["teamId"] = team_id
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

        # Conflict without upsert success → edit fallback for affected keys.
        if response.status_code in {400, 409}:
            edited, n = await self._edit_fallback(
                client,
                project=project,
                team_id=team_id,
                mutations=mutations,
                correlation_id=correlation_id,
            )
            return edited, 1 + n

        err = error_for_status(response.status_code, correlation_id=correlation_id)
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
        team_id: str | None,
        correlation_id: str,
    ) -> tuple[list[dict[str, Any]], int]:
        list_url = f"{VERCEL_API}/v9/projects/{quote(project, safe='')}/env"
        params: dict[str, str] = {}
        if team_id:
            params["teamId"] = team_id
        listed = await request_with_retries(
            client, "GET", list_url, params=params, correlation_id=correlation_id
        )
        if listed.status_code != 200:
            raise ListNamesError(
                error_for_status(listed.status_code, correlation_id=correlation_id)
            )
        return _parse_env_list(listed.json()), 1

    async def _delete_many(
        self,
        client: Any,
        *,
        project: str,
        team_id: str | None,
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

        # name+scope → env id (first matching entry)
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
                # Already absent — treat as successful delete for reconcile.
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="applied",
                    effect="deleted",
                )
                continue
            delete_url = (
                f"{VERCEL_API}/v9/projects/{quote(project, safe='')}/env/{quote(env_id, safe='')}"
            )
            params: dict[str, str] = {}
            if team_id:
                params["teamId"] = team_id
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
                        response.status_code,
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
        team_id: str | None,
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
            # Prefer matching inventory kind when the same key exists twice.
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
            edit_params: dict[str, str] = {}
            if team_id:
                edit_params["teamId"] = team_id
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
                        edited.status_code,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
        return results, requests


def _chunks(items: Sequence[PutMutation], size: int) -> list[Sequence[PutMutation]]:
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
            version="0.1.0+v10-env-upsert",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> VercelDestination:
        return VercelDestination(
            manifest=self.manifest,
            environ=services.environ,
            http_client_factory=services.http_client_factory,
        )
