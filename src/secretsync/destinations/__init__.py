"""Destination connectors."""

from secretsync.destinations.fake import builtin_fake_factories
from secretsync.destinations.registry import KNOWN_CONNECTOR_IDS, ConnectorRegistry

__all__ = ["KNOWN_CONNECTOR_IDS", "ConnectorRegistry", "builtin_fake_factories"]
