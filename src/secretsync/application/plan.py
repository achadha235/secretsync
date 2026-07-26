"""Always-write plan compilation with optional plan-time prune reconcile."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio

from secretsync.application.services import AppServices
from secretsync.application.validate import ValidationIssue, ValidationResult, validate_config
from secretsync.config.compose import ComposedSet
from secretsync.config.models import DeploymentDefinition, RootConfig
from secretsync.destinations.base import ListNamesError, OperationContext
from secretsync.domain.errors import (
    SafeError,
    SecretSyncError,
    UnimplementedChangeDetectionError,
    exit_code_for,
)
from secretsync.domain.models import (
    JsonValue,
    Plan,
    PlannedDelete,
    PlannedPut,
    TargetRef,
    ValueKind,
)


@dataclass(frozen=True, slots=True)
class _InventoryUnit:
    destination_id: str
    connector_id: str
    scope: Mapping[str, JsonValue]
    scope_key: str
    kind: ValueKind
    deployment_ids: tuple[str, ...]
    intended_names: frozenset[str]


def build_plan(
    config: RootConfig,
    composed_sets: dict[str, ComposedSet],
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> Plan:
    """Compile a value-free always-write put plan (no remote calls)."""
    if config.change_detection != "always-write":
        raise UnimplementedChangeDetectionError(config.change_detection)

    from secretsync.application.selection import filter_deployments

    selected = filter_deployments(config, deployments=deployments, destinations=destinations)
    puts: list[PlannedPut] = []
    for deployment in selected:
        available = composed_sets[deployment.set]
        for logical_id, destination_name in deployment.secrets.items():
            source = available.require(
                logical_id,
                deployment=deployment.name,
                destination=deployment.destination,
            )
            puts.append(
                PlannedPut(
                    mutation_id=stable_mutation_id(deployment.name, destination_name),
                    deployment_id=deployment.name,
                    source=source,
                    target=compile_target(config, deployment, destination_name),
                )
            )
        for logical_id, destination_name in deployment.variables.items():
            source = available.require(
                logical_id,
                deployment=deployment.name,
                destination=deployment.destination,
            )
            puts.append(
                PlannedPut(
                    mutation_id=stable_mutation_id(deployment.name, destination_name),
                    deployment_id=deployment.name,
                    source=source,
                    target=compile_target(config, deployment, destination_name),
                )
            )
    return Plan(strategy="always-write", puts=tuple(puts), deletes=())


async def build_plan_async(
    services: AppServices,
    config: RootConfig,
    composed_sets: dict[str, ComposedSet],
    *,
    prune: bool = False,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> Plan:
    """Compile puts; when prune=True, list remotes and add PlannedDeletes for orphans."""
    plan = build_plan(
        config,
        composed_sets,
        deployments=deployments,
        destinations=destinations,
    )
    if not prune:
        return plan

    from secretsync.application.selection import filter_deployments

    selected = filter_deployments(config, deployments=deployments, destinations=destinations)
    units = _inventory_units(config, selected)
    deletes: list[PlannedDelete] = []
    for unit in units:
        destination = config.destinations[unit.destination_id]
        instance = services.connectors.create(unit.connector_id, services)
        caps = instance.manifest.capabilities
        if not caps.list_names or not caps.delete_batch.supported:
            raise SecretSyncError(
                SafeError(
                    code="DESTINATION_INVALID",
                    message=(
                        f"Destination '{unit.destination_id}' "
                        f"[{unit.connector_id}] does not support prune "
                        "(list_names + delete required)"
                    ),
                    destination_id=unit.destination_id,
                    hint="Omit --prune for this destination, or use a connector that supports it.",
                )
            )
        dest_config = _destination_config_map(destination)
        context = OperationContext(correlation_id=str(uuid.uuid4()))
        try:
            remote = await instance.list_names(
                dest_config,
                dict(unit.scope),
                context,
                kind=unit.kind,
            )
        except ListNamesError as exc:
            raise SecretSyncError(
                SafeError(
                    code=exc.safe.code,
                    message=f"{unit.destination_id}: {exc.safe.message}",
                    hint=exc.safe.hint,
                    destination_id=unit.destination_id,
                    correlation_id=exc.safe.correlation_id or context.correlation_id,
                    retryable=exc.safe.retryable,
                )
            ) from exc
        orphans = sorted(remote - unit.intended_names)
        owner_deployment = unit.deployment_ids[0]
        for name in orphans:
            deletes.append(
                PlannedDelete(
                    mutation_id=stable_delete_mutation_id(
                        unit.destination_id, unit.scope_key, unit.kind, name
                    ),
                    deployment_id=owner_deployment,
                    target=TargetRef(
                        destination_id=unit.destination_id,
                        connector_id=unit.connector_id,
                        name=name,
                        scope=dict(unit.scope),
                    ),
                    kind=unit.kind,
                )
            )
    return Plan(strategy="always-write", puts=plan.puts, deletes=tuple(deletes))


def _inventory_units(
    config: RootConfig,
    selected: list[DeploymentDefinition],
) -> list[_InventoryUnit]:
    """Group selected deployments into destination+scope+kind inventory units."""
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for deployment in selected:
        destination = config.destinations[deployment.destination]
        scope = {str(k): _json_value(v) for k, v in deployment.scope.items()}
        scope_key = freeze_scope_key(scope)
        for kind, names in (
            (ValueKind.SECRET, deployment.secrets.values()),
            (ValueKind.VARIABLE, deployment.variables.values()),
        ):
            name_list = list(names)
            if not name_list and kind is ValueKind.VARIABLE and not deployment.variables:
                # Only create a unit when the deployment publishes that kind.
                continue
            if not name_list and kind is ValueKind.SECRET and not deployment.secrets:
                continue
            if not name_list:
                continue
            key = (deployment.destination, scope_key, kind.value)
            bucket = grouped.get(key)
            if bucket is None:
                bucket = {
                    "destination_id": deployment.destination,
                    "connector_id": destination.connector,
                    "scope": scope,
                    "scope_key": scope_key,
                    "kind": kind,
                    "deployment_ids": [],
                    "intended_names": set(),
                }
                grouped[key] = bucket
            if deployment.name not in bucket["deployment_ids"]:
                bucket["deployment_ids"].append(deployment.name)
            bucket["intended_names"].update(name_list)

    units: list[_InventoryUnit] = []
    for bucket in grouped.values():
        units.append(
            _InventoryUnit(
                destination_id=bucket["destination_id"],
                connector_id=bucket["connector_id"],
                scope=bucket["scope"],
                scope_key=bucket["scope_key"],
                kind=bucket["kind"],
                deployment_ids=tuple(bucket["deployment_ids"]),
                intended_names=frozenset(bucket["intended_names"]),
            )
        )
    return units


def freeze_scope_key(scope: Mapping[str, JsonValue]) -> str:
    """Stable inventory key for a deployment scope (order-independent)."""
    return repr(_freeze_json(dict(scope)))


def _freeze_json(value: JsonValue) -> Any:
    if isinstance(value, dict):
        return tuple(sorted((str(k), _freeze_json(v)) for k, v in value.items()))
    if isinstance(value, list):
        # targets arrays: order-independent for inventory identity
        frozen_items = [_freeze_json(v) for v in value]
        try:
            return tuple(sorted(frozen_items, key=repr))
        except TypeError:
            return tuple(frozen_items)
    return value


def stable_mutation_id(deployment_name: str, destination_name: str) -> str:
    return f"{deployment_name}:{destination_name}"


def stable_delete_mutation_id(
    destination_id: str,
    scope_key: str,
    kind: ValueKind,
    name: str,
) -> str:
    return f"{destination_id}:{scope_key}:{kind.value}:delete:{name}"


def compile_target(
    config: RootConfig,
    deployment: DeploymentDefinition,
    destination_name: str,
) -> TargetRef:
    destination = config.destinations[deployment.destination]
    scope: dict[str, JsonValue] = {str(k): _json_value(v) for k, v in deployment.scope.items()}
    return TargetRef(
        destination_id=deployment.destination,
        connector_id=destination.connector,
        name=destination_name,
        scope=scope,
    )


def _destination_config_map(destination: Any) -> dict[str, JsonValue]:
    raw = destination.model_dump(by_alias=True)
    return {str(k): _json_value(v) for k, v in raw.items()}


def _json_value(value: Any) -> JsonValue:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list):
        return [_json_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_value(v) for k, v in value.items()}
    return str(value)


def plan_from_path(
    services: AppServices,
    config_path: Path,
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
    prune: bool = False,
) -> tuple[Plan | None, ValidationResult]:
    """Sync entry: runs async reconcile planner when needed."""

    async def _runner() -> tuple[Plan | None, ValidationResult]:
        return await plan_from_path_async(
            services,
            config_path,
            deployments=deployments,
            destinations=destinations,
            prune=prune,
        )

    return anyio.run(_runner)


async def plan_from_path_async(
    services: AppServices,
    config_path: Path,
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
    prune: bool = False,
) -> tuple[Plan | None, ValidationResult]:
    result = validate_config(
        services,
        config_path,
        deployments=deployments,
        destinations=destinations,
    )
    if not result.ok or result.config is None:
        return None, result
    try:
        plan = await build_plan_async(
            services,
            result.config,
            result.composed_sets,
            prune=prune,
            deployments=deployments,
            destinations=destinations,
        )
        return plan, result
    except SecretSyncError as exc:
        result.issues.append(
            ValidationIssue(code=exc.code, message=exc.safe.message, hint=exc.safe.hint)
        )
        result.exit_code = exit_code_for(exc)
        return None, result
