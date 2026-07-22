"""Fake connectors that prove connector-owned batching (M2 exit gate)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from math import ceil
from typing import Any

from secretsync.destinations.base import (
    ApplyDestinationRequest,
    ApplyDestinationResult,
    BatchCapability,
    DestinationCapabilities,
    DestinationManifest,
    Issue,
    MutationResult,
    OperationContext,
    PutSemantics,
    SafeConnectorError,
)
from secretsync.domain.models import JsonValue


def _individual_capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=False,
        read_values=False,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(supported=False),
        delete_batch=BatchCapability(supported=False),
        multiple_scopes_per_mutation=False,
        batch_across_scopes=False,
    )


def _batch_capabilities(*, max_items: int = 100) -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=False,
        read_values=False,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(
            supported=True,
            max_items=max_items,
            atomic=False,
            transport="api",
        ),
        delete_batch=BatchCapability(supported=False),
        multiple_scopes_per_mutation=True,
        batch_across_scopes=True,
    )


@dataclass
class FakeDestination:
    """In-memory destination used for contract and apply tests."""

    manifest: DestinationManifest
    fail_names: set[str] = field(default_factory=set)
    fail_batch: bool = False
    last_request: ApplyDestinationRequest | None = None

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        del config
        return []

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        del context
        self.last_request = request
        if self.manifest.capabilities.put_batch.supported:
            return self._apply_batch(request)
        return self._apply_individual(request)

    def _apply_individual(self, request: ApplyDestinationRequest) -> ApplyDestinationResult:
        results: list[MutationResult] = []
        requests_made = 0
        for mutation in request.mutations:
            requests_made += 1
            if mutation.name in self.fail_names:
                results.append(
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="failed",
                        effect=None,
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=f"Fake individual failure for '{mutation.name}'",
                            mutation_id=mutation.mutation_id,
                        ),
                    )
                )
            else:
                results.append(
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="applied",
                        effect="upserted",
                    )
                )
        return ApplyDestinationResult(results=tuple(results), requests_made=requests_made)

    def _apply_batch(self, request: ApplyDestinationRequest) -> ApplyDestinationResult:
        max_items = self.manifest.capabilities.put_batch.max_items or len(request.mutations) or 1
        chunks = max(1, ceil(len(request.mutations) / max_items)) if request.mutations else 0
        if self.fail_batch:
            error = SafeConnectorError(
                code="DESTINATION_INVALID",
                message="Fake batch failure",
                correlation_id="fake-batch",
            )
            failed = tuple(
                MutationResult(
                    mutation_id=m.mutation_id,
                    status="failed",
                    effect=None,
                    error=error,
                )
                for m in request.mutations
            )
            return ApplyDestinationResult(results=failed, requests_made=chunks)

        results: list[MutationResult] = []
        for mutation in request.mutations:
            if mutation.name in self.fail_names:
                results.append(
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="failed",
                        effect=None,
                        error=SafeConnectorError(
                            code="DESTINATION_INVALID",
                            message=f"Fake batch item failure for '{mutation.name}'",
                            mutation_id=mutation.mutation_id,
                        ),
                    )
                )
            else:
                results.append(
                    MutationResult(
                        mutation_id=mutation.mutation_id,
                        status="applied",
                        effect="upserted",
                    )
                )
        return ApplyDestinationResult(results=tuple(results), requests_made=chunks)


@dataclass(frozen=True, slots=True)
class FakeIndividualFactory:
    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="fake-individual",
            version="0.1.0",
            capabilities=_individual_capabilities(),
        )
    )

    def create(self, services: Any) -> FakeDestination:
        del services
        return FakeDestination(manifest=self.manifest)


@dataclass(frozen=True, slots=True)
class FakeBatchFactory:
    max_items: int = 100
    manifest: DestinationManifest = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "manifest",
            DestinationManifest(
                id="fake-batch",
                version="0.1.0",
                capabilities=_batch_capabilities(max_items=self.max_items),
            ),
        )

    def create(self, services: Any) -> FakeDestination:
        del services
        return FakeDestination(manifest=self.manifest)


def builtin_fake_factories() -> tuple[FakeIndividualFactory, FakeBatchFactory]:
    return (FakeIndividualFactory(), FakeBatchFactory())
