"""Always-write plan compilation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secretsync.application.services import AppServices
from secretsync.application.validate import ValidationIssue, ValidationResult, validate_config
from secretsync.config.compose import ComposedSet
from secretsync.config.models import DeploymentDefinition, RootConfig
from secretsync.domain.errors import (
    SecretSyncError,
    UnimplementedChangeDetectionError,
    exit_code_for,
)
from secretsync.domain.models import JsonValue, Plan, PlannedPut, TargetRef


def build_plan(
    config: RootConfig,
    composed_sets: dict[str, ComposedSet],
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> Plan:
    """Compile a value-free always-write plan (optionally filtered)."""
    if config.change_detection != "always-write":
        raise UnimplementedChangeDetectionError(config.change_detection)

    from secretsync.application.selection import filter_deployments

    selected = filter_deployments(config, deployments=deployments, destinations=destinations)
    puts: list[PlannedPut] = []
    for deployment in selected:
        available = composed_sets[deployment.set]
        for logical_id, destination_name in deployment.secrets.items():
            source = available.require(logical_id)
            puts.append(
                PlannedPut(
                    mutation_id=stable_mutation_id(deployment.name, destination_name),
                    deployment_id=deployment.name,
                    source=source,
                    target=compile_target(config, deployment, destination_name),
                )
            )
    return Plan(strategy="always-write", puts=tuple(puts))


def stable_mutation_id(deployment_name: str, destination_name: str) -> str:
    return f"{deployment_name}:{destination_name}"


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
        plan = build_plan(
            result.config,
            result.composed_sets,
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
