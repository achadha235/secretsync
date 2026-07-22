"""First-party connector registry (empty until M2/M3/M4)."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Protocol

from secretsync.destinations.base import Destination, DestinationManifest
from secretsync.domain.errors import UnknownConnectorError

# Known connector ids for offline config validation in M0/M1.
# Factories are registered in later milestones.
KNOWN_CONNECTOR_IDS: frozenset[str] = frozenset(
    {
        "github-actions",
        "vercel",
        "sst",
    }
)


class DestinationFactory(Protocol):
    manifest: DestinationManifest

    def create(self, services: Any) -> Destination: ...


class ConnectorRegistry:
    def __init__(self, builtins: Iterable[DestinationFactory] = ()) -> None:
        self._factories = {factory.manifest.id: factory for factory in builtins}

    def known_ids(self) -> list[str]:
        registered = sorted(self._factories)
        if registered:
            return registered
        return sorted(KNOWN_CONNECTOR_IDS)

    def is_known(self, connector_id: str) -> bool:
        return connector_id in self._factories or connector_id in KNOWN_CONNECTOR_IDS

    def create(self, connector_id: str, services: Any) -> Destination:
        try:
            return self._factories[connector_id].create(services)
        except KeyError as exc:
            raise UnknownConnectorError(connector_id) from exc

    def list_manifests(self) -> list[dict[str, str]]:
        if self._factories:
            return [
                {
                    "id": factory.manifest.id,
                    "version": factory.manifest.version,
                    "status": "registered",
                }
                for factory in self._factories.values()
            ]
        return [
            {"id": connector_id, "version": "0.0.0-planned", "status": "planned"}
            for connector_id in sorted(KNOWN_CONNECTOR_IDS)
        ]
