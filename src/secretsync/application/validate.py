"""Offline validation: parse, compose, environment presence, connector ids."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger

from secretsync.application.selection import filter_deployments
from secretsync.application.services import AppServices
from secretsync.config.compose import ComposedSet, compose_from_config
from secretsync.config.models import DeploymentDefinition, RootConfig
from secretsync.destinations.registry import ConnectorRegistry
from secretsync.domain.errors import (
    AuthMissingError,
    ConfigInvalidError,
    SecretSyncError,
    SourceMissingError,
    UnimplementedChangeDetectionError,
    exit_code_for,
)


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: str
    message: str
    hint: str | None = None


@dataclass(slots=True)
class ValidationResult:
    config: RootConfig | None = None
    composed_sets: dict[str, ComposedSet] = field(default_factory=dict)
    issues: list[ValidationIssue] = field(default_factory=list)
    exit_code: int = 0
    selected_deployments: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and self.config is not None


def validate_config(
    services: AppServices,
    config_path: Path,
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> ValidationResult:
    """Run offline validation phases. Never resolves secret values."""
    try:
        logger.info("Loading config {}", config_path)
        config = services.config_loader.load(config_path)
        return validate_loaded(
            services,
            config,
            deployments=deployments,
            destinations=destinations,
        )
    except SecretSyncError as exc:
        return ValidationResult(
            issues=[ValidationIssue(code=exc.code, message=exc.safe.message, hint=exc.safe.hint)],
            exit_code=exit_code_for(exc),
        )


def validate_loaded(
    services: AppServices,
    config: RootConfig,
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> ValidationResult:
    try:
        _require_supported_strategy(config.change_detection)
        composed = compose_from_config(config)
        selected = filter_deployments(config, deployments=deployments, destinations=destinations)
        logger.info(
            "Validating {} deployment(s): {}",
            len(selected),
            ", ".join(d.name for d in selected),
        )
        _validate_deployments(config, composed, services.connectors, selected)
        _check_environment_presence(config, composed, services.environ, selected)
        return ValidationResult(
            config=config,
            composed_sets=composed,
            exit_code=0,
            selected_deployments=tuple(d.name for d in selected),
        )
    except SecretSyncError as exc:
        return ValidationResult(
            issues=[ValidationIssue(code=exc.code, message=exc.safe.message, hint=exc.safe.hint)],
            exit_code=exit_code_for(exc),
        )


def _require_supported_strategy(strategy: str) -> None:
    if strategy != "always-write":
        raise UnimplementedChangeDetectionError(strategy)


def _validate_deployments(
    config: RootConfig,
    composed: dict[str, ComposedSet],
    connectors: ConnectorRegistry,
    selected: Sequence[DeploymentDefinition],
) -> None:
    seen_targets: set[tuple[str, str, str]] = set()

    for deployment in selected:
        if deployment.set not in composed:
            raise ConfigInvalidError(
                f"Deployment '{deployment.name}' references unknown set '{deployment.set}'"
            )

        if deployment.destination not in config.destinations:
            raise ConfigInvalidError(
                f"Deployment '{deployment.name}' references unknown destination "
                f"'{deployment.destination}'"
            )

        destination = config.destinations[deployment.destination]
        if not connectors.is_known(destination.connector):
            raise ConfigInvalidError(
                f"Destination '{deployment.destination}' uses unknown connector "
                f"'{destination.connector}'"
            )

        available = composed[deployment.set]
        for logical_id, dest_name in deployment.secrets.items():
            available.require(logical_id)
            scope_key = _scope_identity(deployment.scope)
            identity = (deployment.destination, scope_key, dest_name)
            if identity in seen_targets:
                raise ConfigInvalidError(
                    f"Duplicate target identity for secret '{dest_name}' on destination "
                    f"'{deployment.destination}' with scope {deployment.scope!r}"
                )
            seen_targets.add(identity)


def _scope_identity(scope: Mapping[str, object]) -> str:
    items = sorted((str(k), repr(v)) for k, v in scope.items())
    return "|".join(f"{k}={v}" for k, v in items)


def _check_environment_presence(
    config: RootConfig,
    composed: dict[str, ComposedSet],
    environ: Mapping[str, str],
    selected: Sequence[DeploymentDefinition],
) -> None:
    required_source: set[str] = set()
    required_auth: dict[str, str] = {}  # token_env -> dest_id

    for deployment in selected:
        available = composed[deployment.set]
        for logical_id in deployment.secrets:
            ref = available.require(logical_id)
            required_source.add(ref.env_name)

        destination = config.destinations[deployment.destination]
        token_env = _token_env_for(destination)
        if token_env:
            required_auth[token_env] = deployment.destination

    logger.debug("Required source env vars: {}", sorted(required_source))
    for env_name in sorted(required_source):
        if env_name not in environ:
            raise SourceMissingError(env_name)

    for token_env, dest_id in sorted(required_auth.items()):
        if token_env not in environ:
            raise AuthMissingError(token_env, destination_id=dest_id)


def _token_env_for(destination: object) -> str | None:
    auth = getattr(destination, "auth", None)
    if auth is not None:
        return getattr(auth, "token_env", None)
    raw = destination.model_dump(by_alias=True)  # type: ignore[attr-defined]
    auth_block = raw.get("auth")
    if isinstance(auth_block, dict):
        value = auth_block.get("tokenEnv")
        return str(value) if value else None
    return None
