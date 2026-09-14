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
# Vercel REST `target` only accepts these builtins. Custom env slugs (e.g. staging)
# must be sent as `customEnvironmentIds` after resolving via the project API.
BUILTIN_TARGETS = frozenset({"production", "preview", "development"})
# Vercel disallows Sensitive env vars only on Development. Custom environments
# (e.g. staging) and production/preview all allow sensitive.
FORBIDDEN_SENSITIVE_TARGETS = frozenset({"development"})
SCOPE_KIND_ENVIRONMENT = "environment"
SCOPE_KIND_SHARED = "shared-environment"
VALID_SCOPE_KINDS = frozenset({SCOPE_KIND_ENVIRONMENT, SCOPE_KIND_SHARED})


class CustomEnvironmentError(Exception):
    """Raised when a custom environment slug cannot be resolved to an id."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _split_targets(targets: Sequence[str]) -> tuple[list[str], list[str]]:
    """Split scope.targets into builtin target names vs custom environment slugs."""
    builtins: list[str] = []
    custom_slugs: list[str] = []
    for target in targets:
        if target in BUILTIN_TARGETS:
            builtins.append(target)
        else:
            custom_slugs.append(target)
    return builtins, custom_slugs


def _targets_api_fields(
    builtins: Sequence[str], custom_ids: Sequence[str]
) -> dict[str, Any]:
    """Build Vercel API fields satisfying anyOf(target, customEnvironmentIds)."""
    fields: dict[str, Any] = {}
    if builtins:
        fields["target"] = list(builtins)
    if custom_ids:
        fields["customEnvironmentIds"] = list(custom_ids)
    return fields


def _scope_target_strings(scope: Mapping[str, JsonValue]) -> list[str]:
    targets_raw = scope.get("targets")
    if not isinstance(targets_raw, list):
        return []
    return [str(t) for t in targets_raw if isinstance(t, str)]


def _projects_for_custom_resolve(
    scope: Mapping[str, JsonValue],
    *,
    destination_project: str | None,
) -> list[str]:
    if _scope_kind(scope) == SCOPE_KIND_SHARED:
        return sorted(_scope_projects(scope))
    if destination_project:
        return [destination_project]
    return []


def _remote_target_slugs(
    item: Mapping[str, Any],
    id_to_slug: Mapping[str, str],
) -> set[str] | None:
    """Normalize remote target + customEnvironmentIds to a set of yaml slugs."""
    remote_targets = item.get("target") or item.get("targets") or []
    if not isinstance(remote_targets, list):
        return None
    slugs = {str(t) for t in remote_targets}
    custom_ids = item.get("customEnvironmentIds") or []
    if custom_ids is None:
        custom_ids = []
    if not isinstance(custom_ids, list):
        return None
    for custom_id in custom_ids:
        slug = id_to_slug.get(str(custom_id))
        if slug is None:
            return None
        slugs.add(slug)
    return slugs


@dataclass
class _CustomEnvResolver:
    """Caches GET /v9/projects/{project}/custom-environments per project."""

    client: Any
    team_id: str
    correlation_id: str
    _slug_by_project: dict[str, dict[str, str]] = field(default_factory=dict)
    _id_to_slug: dict[str, str] = field(default_factory=dict)
    requests_made: int = 0

    @property
    def id_to_slug(self) -> Mapping[str, str]:
        return self._id_to_slug

    async def ensure_projects(self, projects: Sequence[str]) -> None:
        for project in projects:
            if project in self._slug_by_project:
                continue
            slug_to_id = await self._fetch(project)
            self._slug_by_project[project] = slug_to_id
            for slug, env_id in slug_to_id.items():
                self._id_to_slug[env_id] = slug

    async def _fetch(self, project: str) -> dict[str, str]:
        url = (
            f"{VERCEL_API}/v9/projects/{quote(project, safe='')}/custom-environments"
        )
        params: dict[str, str] = {"teamId": self.team_id}
        response = await request_with_retries(
            self.client,
            "GET",
            url,
            params=params,
            correlation_id=self.correlation_id,
        )
        self.requests_made += 1
        if response.status_code != 200:
            raise ListNamesError(
                error_for_status(response, correlation_id=self.correlation_id)
            )
        payload = response.json()
        environments = payload.get("environments") if isinstance(payload, dict) else None
        if not isinstance(environments, list):
            return {}
        result: dict[str, str] = {}
        for env in environments:
            if not isinstance(env, dict):
                continue
            slug = env.get("slug")
            env_id = env.get("id")
            if isinstance(slug, str) and slug and isinstance(env_id, str) and env_id:
                result[slug] = env_id
        return result

    async def resolve_ids(
        self, projects: Sequence[str], slugs: Sequence[str]
    ) -> list[str]:
        """Resolve custom slugs on each project; return union of env ids."""
        if not slugs:
            return []
        if not projects:
            raise CustomEnvironmentError(
                "custom environment targets require a project "
                "(destination.project or scope.projects) to resolve customEnvironmentIds"
            )
        await self.ensure_projects(projects)
        ids: list[str] = []
        seen: set[str] = set()
        for slug in slugs:
            for project in projects:
                env_id = self._slug_by_project[project].get(slug)
                if env_id is None:
                    raise CustomEnvironmentError(
                        f"custom environment '{slug}' not found on project '{project}'; "
                        "create it in the Vercel dashboard (Environments) before syncing"
                    )
                if env_id not in seen:
                    ids.append(env_id)
                    seen.add(env_id)
        return ids

    async def api_fields_for_scope(
        self,
        scope: Mapping[str, JsonValue],
        *,
        destination_project: str | None,
    ) -> dict[str, Any]:
        targets = _scope_target_strings(scope)
        builtins, custom_slugs = _split_targets(targets)
        custom_ids = await self.resolve_ids(
            _projects_for_custom_resolve(scope, destination_project=destination_project),
            custom_slugs,
        )
        return _targets_api_fields(builtins, custom_ids)


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
        illegal = [t for t in targets if t in FORBIDDEN_SENSITIVE_TARGETS]
        if illegal:
            return (
                "sensitive (secret) variables cannot target development "
                "(use production, preview, or a custom environment)"
            )

    git_branch = scope.get("gitBranch")
    projects = scope.get("projects")
    _, custom_slugs = _split_targets([str(t) for t in targets])

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
    if custom_slugs and not _scope_projects(scope):
        return (
            "custom environment targets require scope.projects for "
            "scope.kind=shared-environment (to resolve customEnvironmentIds per project)"
        )
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
    id_to_slug: Mapping[str, str] | None = None,
) -> bool:
    """True when remote target set equals scope.targets (exact ownership).

    Remote rows may store builtins in `target` and custom envs in
    `customEnvironmentIds`; both are normalized to yaml slugs before compare.
    Overlap matching is wrong: a shared deployment with targets [production, preview]
    must not own (list/update/prune) rows that only target production or only preview.
    """
    targets_raw = scope.get("targets")
    if not isinstance(targets_raw, list):
        return False
    wanted = {str(t) for t in targets_raw}
    remote = _remote_target_slugs(item, id_to_slug or {})
    if remote is None or wanted != remote:
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
    id_to_slug: Mapping[str, str] | None = None,
) -> bool:
    """True when a remote env entry belongs to the deployment inventory unit."""
    if not _targets_and_type_match(item, scope, kind=kind, id_to_slug=id_to_slug):
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
                resolver = _CustomEnvResolver(
                    client=client,
                    team_id=team_id,
                    correlation_id=context.correlation_id,
                )
                projects = _projects_for_custom_resolve(
                    scope, destination_project=project
                )
                _, custom_slugs = _split_targets(_scope_target_strings(scope))
                if custom_slugs:
                    await resolver.ensure_projects(projects)
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
        except CustomEnvironmentError as exc:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=exc.message,
                    correlation_id=context.correlation_id,
                )
            ) from exc
        names = {
            str(item["key"])
            for item in envs
            if "key" in item
            and _env_matches_scope(
                item, scope, kind=kind, id_to_slug=resolver.id_to_slug
            )
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
            resolver = _CustomEnvResolver(
                client=client,
                team_id=team_id,
                correlation_id=context.correlation_id,
            )
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
                        resolver=resolver,
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
                        resolver=resolver,
                    )
                    requests_made += n
                    results.update(delete_results)

            if shared_puts:
                put_results, n = await self._upsert_shared(
                    client,
                    team_id=team_id,
                    mutations=shared_puts,
                    correlation_id=context.correlation_id,
                    resolver=resolver,
                )
                requests_made += n
                results.update(put_results)
            if shared_deletes:
                delete_results, n = await self._delete_shared(
                    client,
                    team_id=team_id,
                    deletes=shared_deletes,
                    correlation_id=context.correlation_id,
                    resolver=resolver,
                )
                requests_made += n
                results.update(delete_results)
            requests_made += resolver.requests_made

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
        resolver: _CustomEnvResolver,
    ) -> tuple[dict[str, MutationResult], int]:
        payload = []
        ready: list[PutMutation] = []
        early_failures: dict[str, MutationResult] = {}
        for mutation in mutations:
            scope = dict(mutation.scopes[0])
            try:
                target_fields = await resolver.api_fields_for_scope(
                    scope, destination_project=project
                )
            except CustomEnvironmentError as exc:
                early_failures[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=exc.message,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            except ListNamesError as exc:
                early_failures[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            except HttpRequestError as exc:
                early_failures[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            entry: dict[str, Any] = {
                "key": mutation.name,
                "value": bytes(mutation.value).decode("utf-8"),
                "type": _env_type(mutation.kind),
                **target_fields,
            }
            if scope.get("gitBranch"):
                entry["gitBranch"] = scope["gitBranch"]
            payload.append(entry)
            ready.append(mutation)

        if not ready:
            return early_failures, 0

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
                    **early_failures,
                    **{
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
                        for m in ready
                    },
                },
                1,
            )

        if response.status_code in {200, 201}:
            return (
                {
                    **early_failures,
                    **{
                        m.mutation_id: MutationResult(
                            mutation_id=m.mutation_id,
                            status="applied",
                            effect="upserted",
                        )
                        for m in ready
                    },
                },
                1,
            )

        if response.status_code in {400, 409}:
            edited, n = await self._edit_fallback(
                client,
                project=project,
                team_id=team_id,
                mutations=ready,
                correlation_id=correlation_id,
                resolver=resolver,
            )
            return {**early_failures, **edited}, 1 + n

        err = error_for_status(
            response,
            correlation_id=correlation_id,
            secrets=[bytes(m.value).decode("utf-8", errors="replace") for m in ready],
        )
        return (
            {
                **early_failures,
                **{
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
                    for m in ready
                },
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
        resolver: _CustomEnvResolver,
    ) -> tuple[dict[str, MutationResult], int]:
        try:
            for mutation in mutations:
                scope = dict(mutation.scopes[0])
                _, custom_slugs = _split_targets(_scope_target_strings(scope))
                if custom_slugs:
                    await resolver.ensure_projects(
                        _projects_for_custom_resolve(scope, destination_project=None)
                    )
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
        except CustomEnvironmentError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=exc.message,
                            mutation_id=m.mutation_id,
                            correlation_id=correlation_id,
                        ),
                    )
                    for m in mutations
                },
                0,
            )

        to_update: list[tuple[PutMutation, str]] = []
        to_create: list[PutMutation] = []
        for mutation in mutations:
            scope = dict(mutation.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") == mutation.name and _env_matches_scope(
                    item,
                    scope,
                    kind=mutation.kind,
                    id_to_slug=resolver.id_to_slug,
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
                resolver=resolver,
            )
            requests += n
            results.update(chunk_results)

        # Create batches share type + logical targets + projectId at the request level.
        groups: dict[tuple[str, tuple[str, ...], tuple[str, ...]], list[PutMutation]] = {}
        for mutation in to_create:
            scope = dict(mutation.scopes[0])
            targets = tuple(sorted(_scope_target_strings(scope)))
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
                    resolver=resolver,
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
        resolver: _CustomEnvResolver,
    ) -> tuple[dict[str, MutationResult], int]:
        builtins, custom_slugs = _split_targets(targets)
        try:
            custom_ids = await resolver.resolve_ids(projects, custom_slugs)
        except CustomEnvironmentError as exc:
            return (
                {
                    m.mutation_id: MutationResult(
                        mutation_id=m.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=exc.message,
                            mutation_id=m.mutation_id,
                            correlation_id=correlation_id,
                        ),
                    )
                    for m in mutations
                },
                0,
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
                0,
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
                0,
            )
        body: dict[str, Any] = {
            "evs": [
                {
                    "key": m.name,
                    "value": bytes(m.value).decode("utf-8"),
                }
                for m in mutations
            ],
            "type": env_type,
            **_targets_api_fields(builtins, custom_ids),
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
        resolver: _CustomEnvResolver,
    ) -> tuple[dict[str, MutationResult], int]:
        payload_updates: dict[str, Any] = {}
        early_failures: dict[str, MutationResult] = {}
        for mutation, env_id in updates:
            scope = dict(mutation.scopes[0])
            try:
                target_fields = await resolver.api_fields_for_scope(
                    scope, destination_project=None
                )
            except CustomEnvironmentError as exc:
                early_failures[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=exc.message,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            except ListNamesError as exc:
                early_failures[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            except HttpRequestError as exc:
                early_failures[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            entry: dict[str, Any] = {
                "value": bytes(mutation.value).decode("utf-8"),
                "type": _env_type(mutation.kind),
                **target_fields,
            }
            projects = sorted(_scope_projects(scope))
            if projects:
                entry["projectId"] = projects
            payload_updates[env_id] = entry
        if not payload_updates:
            return early_failures, 0
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
                    **early_failures,
                    **{
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
                        if m.mutation_id not in early_failures
                    },
                },
                1,
            )
        if response.status_code in {200, 201}:
            return (
                {
                    **early_failures,
                    **{
                        m.mutation_id: MutationResult(
                            mutation_id=m.mutation_id,
                            status="applied",
                            effect="updated",
                        )
                        for m, _ in updates
                        if m.mutation_id not in early_failures
                    },
                },
                1,
            )
        err = error_for_status(
            response,
            correlation_id=correlation_id,
            secrets=[
                bytes(m.value).decode("utf-8", errors="replace")
                for m, _ in updates
                if m.mutation_id not in early_failures
            ],
        )
        return (
            {
                **early_failures,
                **{
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
                    if m.mutation_id not in early_failures
                },
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
        resolver: _CustomEnvResolver,
    ) -> tuple[dict[str, MutationResult], int]:
        try:
            for deletion in deletes:
                scope = dict(deletion.scopes[0])
                _, custom_slugs = _split_targets(_scope_target_strings(scope))
                if custom_slugs:
                    await resolver.ensure_projects(
                        _projects_for_custom_resolve(scope, destination_project=None)
                    )
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
        except CustomEnvironmentError as exc:
            return (
                {
                    d.mutation_id: MutationResult(
                        mutation_id=d.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=exc.message,
                            mutation_id=d.mutation_id,
                            correlation_id=correlation_id,
                        ),
                    )
                    for d in deletes
                },
                0,
            )

        results: dict[str, MutationResult] = {}
        pending: list[tuple[DeleteMutation, str]] = []
        for deletion in deletes:
            scope = dict(deletion.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") == deletion.name and _env_matches_scope(
                    item,
                    scope,
                    kind=deletion.kind,
                    id_to_slug=resolver.id_to_slug,
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
        resolver: _CustomEnvResolver,
    ) -> tuple[dict[str, MutationResult], int]:
        try:
            for deletion in deletes:
                scope = dict(deletion.scopes[0])
                _, custom_slugs = _split_targets(_scope_target_strings(scope))
                if custom_slugs:
                    await resolver.ensure_projects([project])
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
        except CustomEnvironmentError as exc:
            return (
                {
                    d.mutation_id: MutationResult(
                        mutation_id=d.mutation_id,
                        status="failed",
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=exc.message,
                            mutation_id=d.mutation_id,
                            correlation_id=correlation_id,
                        ),
                    )
                    for d in deletes
                },
                0,
            )

        results: dict[str, MutationResult] = {}
        requests = list_requests
        for deletion in deletes:
            scope = dict(deletion.scopes[0])
            env_id: str | None = None
            for item in envs:
                if item.get("key") == deletion.name and _env_matches_scope(
                    item,
                    scope,
                    kind=deletion.kind,
                    id_to_slug=resolver.id_to_slug,
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
        resolver: _CustomEnvResolver,
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
                if _env_matches_scope(
                    item,
                    scope,
                    kind=mutation.kind,
                    id_to_slug=resolver.id_to_slug,
                ):
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
            try:
                target_fields = await resolver.api_fields_for_scope(
                    scope, destination_project=project
                )
            except CustomEnvironmentError as exc:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=exc.message,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            except ListNamesError as exc:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            except HttpRequestError as exc:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=exc.safe,
                )
                continue
            body = {
                "value": bytes(mutation.value).decode("utf-8"),
                "type": _env_type(mutation.kind),
                **target_fields,
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
            version="0.3.0+custom-env",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> VercelDestination:
        return VercelDestination(
            manifest=self.manifest,
            environ=services.environ,
            http_client_factory=services.http_client_factory,
        )
