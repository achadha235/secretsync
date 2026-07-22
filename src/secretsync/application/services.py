"""Application services composition root."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from secretsync.config.loader import ConfigLoader
from secretsync.destinations.registry import ConnectorRegistry
from secretsync.sources.environment import EnvironmentSource


@dataclass(frozen=True, slots=True)
class AppServices:
    config_loader: ConfigLoader
    source: EnvironmentSource
    connectors: ConnectorRegistry
    environ: Mapping[str, str]


def create_services(environ: Mapping[str, str]) -> AppServices:
    """Composition root. Click and Textual receive this object."""
    return AppServices(
        config_loader=ConfigLoader(),
        source=EnvironmentSource(environ),
        connectors=ConnectorRegistry(),
        environ=environ,
    )
