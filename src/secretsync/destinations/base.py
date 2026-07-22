"""Destination connector protocols and capability types (M2 stubs for M0/M1)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from secretsync.domain.models import JsonValue


class PutSemantics(StrEnum):
    UPSERT = "upsert"
    CREATE_ONLY = "create-only"
    UPDATE_ONLY = "update-only"
    CREATE_AND_UPDATE = "create-and-update"


@dataclass(frozen=True, slots=True)
class BatchCapability:
    supported: bool
    max_items: int | None = None
    atomic: bool = False
    transport: str | None = None


@dataclass(frozen=True, slots=True)
class DestinationCapabilities:
    list_names: bool
    read_values: bool
    put_semantics: PutSemantics
    put_batch: BatchCapability
    delete_batch: BatchCapability
    multiple_scopes_per_mutation: bool
    batch_across_scopes: bool


@dataclass(frozen=True, slots=True)
class DestinationManifest:
    id: str
    version: str
    capabilities: DestinationCapabilities


class Destination(Protocol):
    manifest: DestinationManifest

    async def validate(self, config: Mapping[str, JsonValue]) -> list[str]: ...
