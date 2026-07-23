"""Deployment selection for validate/plan/apply."""

from __future__ import annotations

from collections.abc import Sequence

from secretsync.config.models import DeploymentDefinition, RootConfig
from secretsync.domain.errors import ConfigInvalidError


def filter_deployments(
    config: RootConfig,
    *,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> list[DeploymentDefinition]:
    """Return matching deployments. Empty filters mean all. Unknown names error."""
    if deployments:
        known = {d.name for d in config.deployments}
        missing = sorted(deployments - known)
        if missing:
            raise ConfigInvalidError(
                f"Unknown deployment(s): {', '.join(missing)}",
                hint="Check deployments[].name in secretsync.yaml",
            )
    if destinations:
        known_dest = set(config.destinations)
        missing_d = sorted(destinations - known_dest)
        if missing_d:
            raise ConfigInvalidError(
                f"Unknown destination(s): {', '.join(missing_d)}",
                hint="Check destinations keys in secretsync.yaml",
            )

    selected: list[DeploymentDefinition] = []
    for deployment in config.deployments:
        if deployments and deployment.name not in deployments:
            continue
        if destinations and deployment.destination not in destinations:
            continue
        selected.append(deployment)

    if (deployments or destinations) and not selected:
        raise ConfigInvalidError(
            "No deployments match the given --deployment/--destination filters",
        )
    return selected


def selection_extra(deployments: Sequence[str], destinations: Sequence[str]) -> str:
    bits: list[str] = []
    if deployments:
        bits.append("deployments=" + ",".join(sorted(deployments)))
    if destinations:
        bits.append("destinations=" + ",".join(sorted(destinations)))
    return " ".join(bits)
