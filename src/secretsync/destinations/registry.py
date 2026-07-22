"""First-party connector registry."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from secretsync.destinations.base import Destination, DestinationManifest
from secretsync.domain.errors import ConnectorNotImplementedError, UnknownConnectorError

# Planned real connectors (validated offline; factories arrive in M3/M4).
PLANNED_CONNECTOR_IDS: frozenset[str] = frozenset(
    {
        "github-actions",
        "vercel",
        "sst",
    }
)

# Backward-compatible alias used by validate.
KNOWN_CONNECTOR_IDS: frozenset[str] = PLANNED_CONNECTOR_IDS


class DestinationFactory(Protocol):
    manifest: DestinationManifest

    def create(self, services: Any) -> Destination: ...


class ConnectorRegistry:
    def __init__(self, builtins: Iterable[DestinationFactory] = ()) -> None:
        self._factories: dict[str, DestinationFactory] = {
            factory.manifest.id: factory for factory in builtins
        }

    def known_ids(self) -> list[str]:
        return sorted(set(self._factories) | set(PLANNED_CONNECTOR_IDS))

    def is_known(self, connector_id: str) -> bool:
        return connector_id in self._factories or connector_id in PLANNED_CONNECTOR_IDS

    def is_registered(self, connector_id: str) -> bool:
        return connector_id in self._factories

    def create(self, connector_id: str, services: Any) -> Destination:
        factory = self._factories.get(connector_id)
        if factory is not None:
            return factory.create(services)
        if connector_id in PLANNED_CONNECTOR_IDS:
            raise ConnectorNotImplementedError(connector_id)
        raise UnknownConnectorError(connector_id)

    def list_manifests(self) -> list[dict[str, str]]:
        items: list[dict[str, str]] = [
            {
                "id": factory.manifest.id,
                "version": factory.manifest.version,
                "status": "registered",
            }
            for factory in sorted(self._factories.values(), key=lambda f: f.manifest.id)
        ]
        for connector_id in sorted(PLANNED_CONNECTOR_IDS):
            if connector_id not in self._factories:
                items.append(
                    {
                        "id": connector_id,
                        "version": "0.0.0-planned",
                        "status": "planned",
                    }
                )
        return items
