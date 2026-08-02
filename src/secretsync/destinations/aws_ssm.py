"""AWS Systems Manager Parameter Store destination via boto3."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

import anyio

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
from secretsync.infrastructure.redaction import sanitize_provider_message

BOTO3_INSTALL_HINT = (
    "Install the AWS extra: pip install 'secretsync-cli[aws]' "
    "(or 'secretsync-cli[all]')."
)
VALID_TIERS = frozenset({"Standard", "Advanced", "Intelligent-Tiering"})
# Relative segment or multi-segment path (no leading slash). Full names validated after join.
RELATIVE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*$")
# Fully qualified parameter name after pathPrefix join.
FULL_NAME_RE = re.compile(r"^/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+$")
RESERVED_PREFIX_RE = re.compile(r"^/(aws|ssm)(/|$)", re.IGNORECASE)
DELETE_BATCH_MAX = 10

SsmClientFactory = Callable[[str | None], Any]


class Boto3MissingError(Exception):
    """Raised when the optional boto3 extra is not installed."""

    def __init__(self, safe: SafeConnectorError) -> None:
        self.safe = safe
        super().__init__(safe.message)


def _capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=True,
        read_values=False,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(supported=False),
        delete_batch=BatchCapability(supported=True, max_items=DELETE_BATCH_MAX),
        multiple_scopes_per_mutation=False,
        batch_across_scopes=False,
    )


def _import_boto3() -> Any:
    try:
        import boto3  # type: ignore[import-untyped]
    except ImportError as exc:
        raise Boto3MissingError(
            SafeConnectorError(
                code="DEPENDENCY_MISSING",
                message="boto3 is required for the aws-ssm connector",
                hint=BOTO3_INSTALL_HINT,
            )
        ) from exc
    return boto3


def _default_ssm_client(region: str | None) -> Any:
    boto3_mod = _import_boto3()
    kwargs: dict[str, Any] = {}
    if region:
        kwargs["region_name"] = region
    return boto3_mod.client("ssm", **kwargs)


def _region(config: Mapping[str, JsonValue]) -> str | None:
    raw = config.get("region")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        return ""
    return raw.strip()


def _key_id(config: Mapping[str, JsonValue]) -> str | None:
    raw = config.get("keyId")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        return ""
    return raw.strip()


def _tier(config: Mapping[str, JsonValue]) -> str | None:
    raw = config.get("tier")
    if raw is None:
        return None
    if not isinstance(raw, str) or not raw.strip():
        return ""
    return raw.strip()


def _path_prefix(scope: Mapping[str, JsonValue]) -> str | None:
    raw = scope.get("pathPrefix")
    if not isinstance(raw, str) or not raw.strip():
        return None
    return raw.strip().rstrip("/")


def parameter_type_for_kind(kind: ValueKind) -> str:
    if kind is ValueKind.SECRET:
        return "SecureString"
    return "String"


def join_parameter_name(path_prefix: str, relative_name: str) -> str:
    """Join destination pathPrefix with a relative remote name."""
    prefix = path_prefix if path_prefix.startswith("/") else f"/{path_prefix}"
    prefix = prefix.rstrip("/")
    name = relative_name.strip().lstrip("/")
    return f"{prefix}/{name}"


def relative_parameter_name(path_prefix: str, full_name: str) -> str | None:
    """Strip pathPrefix from a full parameter name; None if outside the prefix."""
    prefix = path_prefix if path_prefix.startswith("/") else f"/{path_prefix}"
    prefix = prefix.rstrip("/")
    if full_name == prefix:
        return None
    if not full_name.startswith(prefix + "/"):
        return None
    return full_name[len(prefix) + 1 :]


def validate_relative_name(name: str) -> str | None:
    if not RELATIVE_NAME_RE.match(name):
        return (
            f"Invalid Parameter Store name '{name}'; use path segments matching "
            "a-zA-Z0-9_.- (optionally separated by '/')"
        )
    return None


def validate_full_name(full_name: str) -> str | None:
    if not FULL_NAME_RE.match(full_name):
        return f"Invalid Parameter Store path '{full_name}'"
    if RESERVED_PREFIX_RE.match(full_name):
        return f"Parameter names must not be prefixed with 'aws' or 'ssm': {full_name}"
    if full_name.count("/") > 15:
        return f"Parameter hierarchy exceeds 15 levels: {full_name}"
    return None


def _config_issues(config: Mapping[str, JsonValue]) -> list[Issue]:
    issues: list[Issue] = []
    region = _region(config)
    if region == "":
        issues.append(
            Issue(code="DESTINATION_INVALID", message="aws-ssm region must be a non-empty string")
        )
    key_id = _key_id(config)
    if key_id == "":
        issues.append(
            Issue(code="DESTINATION_INVALID", message="aws-ssm keyId must be a non-empty string")
        )
    tier = _tier(config)
    if tier == "":
        issues.append(
            Issue(code="DESTINATION_INVALID", message="aws-ssm tier must be a non-empty string")
        )
    elif tier is not None and tier not in VALID_TIERS:
        issues.append(
            Issue(
                code="DESTINATION_INVALID",
                message=(
                    f"aws-ssm tier must be one of: {', '.join(sorted(VALID_TIERS))}"
                ),
            )
        )
    return issues


def _client_error_safe(
    exc: BaseException,
    *,
    correlation_id: str | None = None,
    mutation_id: str | None = None,
    secrets: Sequence[str] | None = None,
) -> SafeConnectorError:
    code = "PROVIDER_ERROR"
    message = sanitize_provider_message(str(exc), list(secrets) if secrets else None)
    retryable = False
    error_code = getattr(exc, "response", None)
    if isinstance(error_code, dict):
        err = error_code.get("Error")
        if isinstance(err, dict):
            aws_code = str(err.get("Code", ""))
            aws_msg = str(err.get("Message", message))
            message = sanitize_provider_message(
                f"{aws_code}: {aws_msg}" if aws_code else aws_msg,
                list(secrets) if secrets else None,
            )
            if aws_code in {"ThrottlingException", "TooManyRequestsException"}:
                retryable = True
                code = "PROVIDER_THROTTLED"
    return SafeConnectorError(
        code=code,
        message=message[:512],
        mutation_id=mutation_id,
        correlation_id=correlation_id,
        retryable=retryable,
    )


@dataclass
class AwsSsmDestination:
    manifest: DestinationManifest
    environ: Mapping[str, str]
    client_factory: SsmClientFactory = field(default=_default_ssm_client)
    _clients: dict[str | None, Any] = field(default_factory=dict)

    def check_kind_support(self, kind: ValueKind) -> Issue | None:
        del kind
        return None

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        return _config_issues(config)

    def _get_client(self, region: str | None) -> Any:
        if region not in self._clients:
            self._clients[region] = self.client_factory(region)
        return self._clients[region]

    async def list_names(
        self,
        config: Mapping[str, JsonValue],
        scope: Mapping[str, JsonValue],
        context: OperationContext,
        *,
        kind: ValueKind = ValueKind.SECRET,
    ) -> frozenset[str]:
        issues = _config_issues(config)
        if issues:
            raise ListNamesError(
                SafeConnectorError(
                    code=issues[0].code,
                    message=issues[0].message,
                    hint=issues[0].hint,
                    correlation_id=context.correlation_id,
                )
            )
        path_prefix = _path_prefix(scope)
        if path_prefix is None:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="aws-ssm scope.pathPrefix is required",
                    correlation_id=context.correlation_id,
                )
            )
        param_type = parameter_type_for_kind(kind)
        region = _region(config) or None
        try:
            client = self._get_client(region)
        except Boto3MissingError as exc:
            raise ListNamesError(
                SafeConnectorError(
                    code=exc.safe.code,
                    message=exc.safe.message,
                    hint=exc.safe.hint,
                    correlation_id=context.correlation_id,
                )
            ) from exc

        names: set[str] = set()
        next_token: str | None = None
        try:
            while True:
                kwargs: dict[str, Any] = {
                    "ParameterFilters": [
                        {
                            "Key": "Name",
                            "Option": "BeginsWith",
                            "Values": [path_prefix],
                        },
                        {
                            "Key": "Type",
                            "Option": "Equals",
                            "Values": [param_type],
                        },
                    ],
                    "MaxResults": 50,
                }
                if next_token:
                    kwargs["NextToken"] = next_token

                def _describe(call_kwargs: dict[str, Any]) -> Any:
                    return client.describe_parameters(**call_kwargs)

                response = await anyio.to_thread.run_sync(_describe, kwargs)
                for item in response.get("Parameters") or []:
                    full = item.get("Name")
                    if not isinstance(full, str):
                        continue
                    relative = relative_parameter_name(path_prefix, full)
                    if relative is not None:
                        names.add(relative)
                next_token = response.get("NextToken")
                if not next_token:
                    break
        except Boto3MissingError as exc:
            raise ListNamesError(
                SafeConnectorError(
                    code=exc.safe.code,
                    message=exc.safe.message,
                    hint=exc.safe.hint,
                    correlation_id=context.correlation_id,
                )
            ) from exc
        except Exception as exc:  # noqa: BLE001 — map provider failures
            raise ListNamesError(
                _client_error_safe(exc, correlation_id=context.correlation_id)
            ) from exc
        return frozenset(names)

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        config = request.destination_config
        all_ids = [m.mutation_id for m in request.mutations] + [
            d.mutation_id for d in request.deletes
        ]
        issues = _config_issues(config)
        if issues:
            return _all_failed_ids(
                all_ids,
                SafeConnectorError(
                    code=issues[0].code,
                    message=issues[0].message,
                    hint=issues[0].hint,
                    correlation_id=context.correlation_id,
                ),
            )

        region = _region(config) or None
        try:
            client = self._get_client(region)
        except Boto3MissingError as exc:
            return _all_failed_ids(
                all_ids,
                SafeConnectorError(
                    code=exc.safe.code,
                    message=exc.safe.message,
                    hint=exc.safe.hint,
                    correlation_id=context.correlation_id,
                ),
            )

        results: dict[str, MutationResult] = {}
        requests_made = 0
        key_id = _key_id(config)
        tier = _tier(config)

        for mutation in request.mutations:
            result, n = await self._put_one(
                client=client,
                mutation=mutation,
                key_id=key_id if key_id else None,
                tier=tier if tier else None,
                correlation_id=context.correlation_id,
            )
            results[mutation.mutation_id] = result
            requests_made += n

        delete_chunks: list[list[DeleteMutation]] = []
        current: list[DeleteMutation] = []
        for deletion in request.deletes:
            if len(current) >= DELETE_BATCH_MAX:
                delete_chunks.append(current)
                current = []
            current.append(deletion)
        if current:
            delete_chunks.append(current)

        for chunk in delete_chunks:
            chunk_results, n = await self._delete_chunk(
                client=client,
                deletes=chunk,
                correlation_id=context.correlation_id,
            )
            results.update(chunk_results)
            requests_made += n

        ordered = tuple(results[mid] for mid in all_ids)
        return ApplyDestinationResult(results=ordered, requests_made=requests_made)

    async def _put_one(
        self,
        *,
        client: Any,
        mutation: PutMutation,
        key_id: str | None,
        tier: str | None,
        correlation_id: str,
    ) -> tuple[MutationResult, int]:
        if not mutation.scopes:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing aws-ssm scope on mutation",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        path_prefix = _path_prefix(dict(mutation.scopes[0]))
        if path_prefix is None:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="aws-ssm scope.pathPrefix is required",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        name_err = validate_relative_name(mutation.name)
        if name_err:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=name_err,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )
        full_name = join_parameter_name(path_prefix, mutation.name)
        full_err = validate_full_name(full_name)
        if full_err:
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=full_err,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                ),
                0,
            )

        value_text = bytes(mutation.value).decode("utf-8")
        param_type = parameter_type_for_kind(mutation.kind)
        kwargs: dict[str, Any] = {
            "Name": full_name,
            "Value": value_text,
            "Type": param_type,
            "Overwrite": True,
        }
        if param_type == "SecureString" and key_id:
            kwargs["KeyId"] = key_id
        if tier:
            kwargs["Tier"] = tier

        try:

            def _put() -> Any:
                return client.put_parameter(**kwargs)

            await anyio.to_thread.run_sync(_put)
        except Exception as exc:  # noqa: BLE001
            return (
                MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=_client_error_safe(
                        exc,
                        correlation_id=correlation_id,
                        mutation_id=mutation.mutation_id,
                        secrets=[value_text],
                    ),
                ),
                1,
            )
        finally:
            kwargs.pop("Value", None)
            del value_text

        return (
            MutationResult(
                mutation_id=mutation.mutation_id,
                status="applied",
                effect="upserted",
            ),
            1,
        )

    async def _delete_chunk(
        self,
        *,
        client: Any,
        deletes: Sequence[DeleteMutation],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        resolved: list[tuple[DeleteMutation, str]] = []
        results: dict[str, MutationResult] = {}
        for deletion in deletes:
            if not deletion.scopes:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing aws-ssm scope on delete",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            path_prefix = _path_prefix(dict(deletion.scopes[0]))
            if path_prefix is None:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="aws-ssm scope.pathPrefix is required",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            name_err = validate_relative_name(deletion.name)
            if name_err:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=name_err,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            full_name = join_parameter_name(path_prefix, deletion.name)
            full_err = validate_full_name(full_name)
            if full_err:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message=full_err,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            resolved.append((deletion, full_name))

        if not resolved:
            return results, 0

        names = [full for _, full in resolved]
        try:

            def _delete() -> Any:
                return client.delete_parameters(Names=names)

            await anyio.to_thread.run_sync(_delete)
        except Exception as exc:  # noqa: BLE001
            error = _client_error_safe(exc, correlation_id=correlation_id)
            for deletion, _ in resolved:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code=error.code,
                        message=error.message,
                        hint=error.hint,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                        retryable=error.retryable,
                    ),
                )
            return results, 1

        for deletion, _ in resolved:
            results[deletion.mutation_id] = MutationResult(
                mutation_id=deletion.mutation_id,
                status="applied",
                effect="deleted",
            )
        return results, 1


def _all_failed_ids(
    mutation_ids: Sequence[str], error: SafeConnectorError
) -> ApplyDestinationResult:
    return ApplyDestinationResult(
        results=tuple(
            MutationResult(mutation_id=mid, status="failed", error=error) for mid in mutation_ids
        ),
        requests_made=0,
    )


@dataclass(frozen=True, slots=True)
class AwsSsmFactory:
    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="aws-ssm",
            version="0.1.0",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> AwsSsmDestination:
        return AwsSsmDestination(
            manifest=self.manifest,
            environ=services.environ,
        )
