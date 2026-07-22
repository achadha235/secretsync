"""Application services composition root."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from secretsync.config.loader import ConfigLoader
from secretsync.destinations.fake import builtin_fake_factories
from secretsync.destinations.github_actions import GitHubActionsFactory
from secretsync.destinations.registry import ConnectorRegistry
from secretsync.destinations.vercel import VercelFactory
from secretsync.infrastructure.http import HttpClientFactory
from secretsync.sources.environment import EnvironmentSource


@dataclass(frozen=True, slots=True)
class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class StubProcessRunner:
    """Secure process runner arrives in M4."""

    async def execute(self, request: Any) -> Any:
        raise NotImplementedError("Secure process runner is implemented in M4")


@dataclass(frozen=True, slots=True)
class AppServices:
    config_loader: ConfigLoader
    source: EnvironmentSource
    connectors: ConnectorRegistry
    environ: Mapping[str, str]
    clock: SystemClock
    http_client_factory: HttpClientFactory
    process_runner: StubProcessRunner


def create_services(environ: Mapping[str, str]) -> AppServices:
    """Composition root. Click and Textual receive this object."""
    factories: list[Any] = [
        *builtin_fake_factories(),
        GitHubActionsFactory(),
        VercelFactory(),
    ]
    return AppServices(
        config_loader=ConfigLoader(),
        source=EnvironmentSource(environ),
        connectors=ConnectorRegistry(factories),
        environ=environ,
        clock=SystemClock(),
        http_client_factory=HttpClientFactory(),
        process_runner=StubProcessRunner(),
    )
