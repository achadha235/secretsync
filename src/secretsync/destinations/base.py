"""Destination connector protocols, capabilities, and apply contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Protocol

from secretsync.domain.errors import SafeError
from secretsync.domain.models import JsonValue, ValueKind

# Spec alias: connector-facing errors are SafeError payloads.
SafeConnectorError = SafeError


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


@dataclass(frozen=True, slots=True)
class Issue:
    code: str
    message: str
    hint: str | None = None


@dataclass(slots=True)
class PutMutation:
    mutation_id: str
    name: str
    value: bytearray
    scopes: tuple[Mapping[str, JsonValue], ...]
    kind: ValueKind = ValueKind.SECRET


@dataclass(slots=True)
class DeleteMutation:
    mutation_id: str
    name: str
    scopes: tuple[Mapping[str, JsonValue], ...]
    kind: ValueKind = ValueKind.SECRET


@dataclass(slots=True)
class ApplyDestinationRequest:
    deployment_id: str
    destination_config: Mapping[str, JsonValue]
    mutations: list[PutMutation]
    deletes: list[DeleteMutation] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class MutationResult:
    mutation_id: str
    status: Literal["applied", "failed", "skipped"]
    effect: Literal["upserted", "created", "updated", "deleted", "unknown"] | None = None
    error: SafeConnectorError | None = None


@dataclass(frozen=True, slots=True)
class ApplyDestinationResult:
    results: tuple[MutationResult, ...]
    requests_made: int = 0


@dataclass(frozen=True, slots=True)
class OperationContext:
    """Value-free context passed into connector apply / list calls."""

    correlation_id: str


class ListNamesError(Exception):
    """Raised when a connector cannot list remote secret names."""

    def __init__(self, safe: SafeConnectorError) -> None:
        self.safe = safe
        super().__init__(safe.message)


class Destination(Protocol):
    manifest: DestinationManifest

    def check_kind_support(self, kind: ValueKind) -> Issue | None:
        """Return None if this connector can publish `kind`, else an Issue to surface."""
        ...

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]: ...

    async def list_names(
        self,
        config: Mapping[str, JsonValue],
        scope: Mapping[str, JsonValue],
        context: OperationContext,
        *,
        kind: ValueKind = ValueKind.SECRET,
    ) -> frozenset[str]: ...

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult: ...
