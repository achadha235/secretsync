"""Set inheritance, overrides, and composed secret/variable availability."""

from __future__ import annotations

from secretsync.config.models import RootConfig, SecretDefinition, SetDefinition
from secretsync.domain.errors import ConfigInvalidError
from secretsync.domain.models import SecretRef, ValueKind


class ComposedSet:
    """Resolved membership for one named set."""

    def __init__(self, set_id: str, members: dict[str, SecretRef]) -> None:
        self.set_id = set_id
        self._members = members
        self.order: tuple[str, ...] = tuple(members.keys())

    def require(
        self,
        logical_id: str,
        *,
        deployment: str | None = None,
        destination: str | None = None,
    ) -> SecretRef:
        try:
            return self._members[logical_id]
        except KeyError as exc:
            where = ""
            if deployment is not None:
                where = f" (deployment '{deployment}'"
                if destination is not None:
                    where += f", destination '{destination}'"
                where += ")"
            raise ConfigInvalidError(
                f"Logical id '{logical_id}' is not available in set '{self.set_id}'{where}",
                hint=(
                    f"Add '{logical_id}' to set '{self.set_id}' (or an ancestor), "
                    f"or point the deployment at a set that includes it."
                    if deployment is not None
                    else None
                ),
            ) from exc

    def get(self, logical_id: str) -> SecretRef | None:
        return self._members.get(logical_id)

    def as_dict(self) -> dict[str, SecretRef]:
        return dict(self._members)


def compose_sets(
    secrets: dict[str, SecretDefinition],
    variables: dict[str, SecretDefinition],
    sets: dict[str, SetDefinition],
) -> dict[str, ComposedSet]:
    """Compose all sets with deterministic inheritance and overrides."""
    catalog = _build_catalog(secrets, variables)

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
            if logical_id not in catalog:
                raise ConfigInvalidError(
                    f"Set '{set_id}' includes unknown id '{logical_id}' "
                    "(not declared under secrets or variables)"
                )
            # Re-including an already inherited member keeps first declaration order.
            if logical_id not in members:
                members[logical_id] = catalog[logical_id]

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
                kind=current.kind,
            )

        visiting.remove(set_id)
        result = ComposedSet(set_id, members)
        composed[set_id] = result
        return result

    for set_id in sets:
        resolve(set_id)
    return composed


def compose_from_config(config: RootConfig) -> dict[str, ComposedSet]:
    return compose_sets(config.secrets, config.variables, config.sets)


def _build_catalog(
    secrets: dict[str, SecretDefinition],
    variables: dict[str, SecretDefinition],
) -> dict[str, SecretRef]:
    catalog: dict[str, SecretRef] = {}
    for logical_id, definition in secrets.items():
        _validate_logical_id(logical_id)
        catalog[logical_id] = SecretRef(
            logical_id=logical_id,
            env_name=definition.env,
            allow_empty=definition.allow_empty,
            kind=ValueKind.SECRET,
        )
    for logical_id, definition in variables.items():
        _validate_logical_id(logical_id)
        catalog[logical_id] = SecretRef(
            logical_id=logical_id,
            env_name=definition.env,
            allow_empty=definition.allow_empty,
            kind=ValueKind.VARIABLE,
        )
    return catalog


def _validate_logical_id(logical_id: str) -> None:
    if not logical_id or not logical_id.strip():
        raise ConfigInvalidError("Logical ids must be non-empty")
