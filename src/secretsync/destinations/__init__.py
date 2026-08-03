"""Destination connectors."""

from secretsync.destinations.aws_ssm import AwsSsmFactory
from secretsync.destinations.fake import builtin_fake_factories
from secretsync.destinations.github_actions import GitHubActionsFactory
from secretsync.destinations.registry import KNOWN_CONNECTOR_IDS, ConnectorRegistry
from secretsync.destinations.sst import SstFactory
from secretsync.destinations.vercel import VercelFactory

__all__ = [
    "KNOWN_CONNECTOR_IDS",
    "AwsSsmFactory",
    "ConnectorRegistry",
    "GitHubActionsFactory",
    "SstFactory",
    "VercelFactory",
    "builtin_fake_factories",
]
