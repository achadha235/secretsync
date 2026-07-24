"""Immutable domain types for planning and apply."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


class Operation(StrEnum):
    PUT = "put"
    DELETE = "delete"


class ValueKind(StrEnum):
    """Whether a logical id is a secret or a non-secret variable."""

    SECRET = "secret"
    VARIABLE = "variable"


@dataclass(frozen=True, slots=True)
class SecretRef:
    """Env-backed value reference (secret or variable)."""

    logical_id: str
    env_name: str
    allow_empty: bool = False
    kind: ValueKind = ValueKind.SECRET


@dataclass(frozen=True, slots=True)
class TargetRef:
    destination_id: str
    connector_id: str
    name: str
    scope: Mapping[str, JsonValue]


@dataclass(frozen=True, slots=True)
class PlannedPut:
    mutation_id: str
    deployment_id: str
    source: SecretRef
    target: TargetRef


@dataclass(frozen=True, slots=True)
class PlannedDelete:
    mutation_id: str
    deployment_id: str
    target: TargetRef
    kind: ValueKind = ValueKind.SECRET


@dataclass(slots=True)
class ResolvedPut:
    """Apply-only; must never reach presentation adapters."""

    planned: PlannedPut
    value: bytearray


@dataclass(frozen=True, slots=True)
class Plan:
    strategy: str
    puts: tuple[PlannedPut, ...]
    deletes: tuple[PlannedDelete, ...] = ()


@dataclass(slots=True)
class SecretMaterial:
    value: bytearray


def scope_as_dict(scope: Mapping[str, Any]) -> dict[str, JsonValue]:
    return dict(scope)
