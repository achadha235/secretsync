"""Set inheritance, overrides, and composed secret availability."""

from __future__ import annotations

from secretsync.config.models import RootConfig, SecretDefinition, SetDefinition
from secretsync.domain.errors import ConfigInvalidError
from secretsync.domain.models import SecretRef


class ComposedSet:
    """Resolved membership for one named set."""

    def __init__(self, set_id: str, members: dict[str, SecretRef]) -> None:
        self.set_id = set_id
        self._members = members
        self.order: tuple[str, ...] = tuple(members.keys())

    def require(self, logical_id: str) -> SecretRef:
        try:
            return self._members[logical_id]
        except KeyError as exc:
            raise ConfigInvalidError(
                f"Logical secret '{logical_id}' is not available in set '{self.set_id}'"
            ) from exc

    def get(self, logical_id: str) -> SecretRef | None:
        return self._members.get(logical_id)

    def as_dict(self) -> dict[str, SecretRef]:
        return dict(self._members)


def compose_sets(
    secrets: dict[str, SecretDefinition],
    sets: dict[str, SetDefinition],
) -> dict[str, ComposedSet]:
    """Compose all sets with deterministic inheritance and overrides."""
    for secret_id in secrets:
        _validate_logical_id(secret_id)

    composed: dict[str, ComposedSet] = {}
    visiting: set[str] = set()

    def resolve(set_id: str) -> ComposedSet:
        if set_id in composed:
            return composed[set_id]
        if set_id not in sets:
            raise ConfigInvalidError(f"Unknown set '{set_id}'")
        if set_id in visiting:
            cycle = " -> ".join([*visiting, set_id])
            raise ConfigInvalidError(f"Set inheritance cycle detected: {cycle}")

        visiting.add(set_id)
        definition = sets[set_id]
        members: dict[str, SecretRef] = {}

        if definition.extends is not None:
            parent = resolve(definition.extends)
            members.update(parent.as_dict())

        for logical_id in definition.include:
            if logical_id not in secrets:
                raise ConfigInvalidError(f"Set '{set_id}' includes unknown secret '{logical_id}'")
            # Re-including an already inherited secret keeps first declaration order.
            if logical_id not in members:
                secret = secrets[logical_id]
                members[logical_id] = SecretRef(
                    logical_id=logical_id,
                    env_name=secret.env,
                    allow_empty=secret.allow_empty,
                )

        for logical_id, override in definition.overrides.items():
            if logical_id not in members:
                raise ConfigInvalidError(
                    f"Set '{set_id}' overrides '{logical_id}' which is not available "
                    "through inheritance or include"
                )
            current = members[logical_id]
            members[logical_id] = SecretRef(
                logical_id=logical_id,
                env_name=override.env if override.env is not None else current.env_name,
                allow_empty=(
                    override.allow_empty
                    if override.allow_empty is not None
                    else current.allow_empty
                ),
            )

        visiting.remove(set_id)
        result = ComposedSet(set_id, members)
        composed[set_id] = result
        return result

    for set_id in sets:
        resolve(set_id)
    return composed


def compose_from_config(config: RootConfig) -> dict[str, ComposedSet]:
    return compose_sets(config.secrets, config.sets)


def _validate_logical_id(logical_id: str) -> None:
    if not logical_id or not logical_id.strip():
        raise ConfigInvalidError("Logical secret ids must be non-empty")
