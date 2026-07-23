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
    DeleteMutation,
    DestinationCapabilities,
    DestinationManifest,
    Issue,
    ListNamesError,
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


def _prune_capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=True,
        read_values=False,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(supported=False),
        delete_batch=BatchCapability(supported=True, max_items=1),
        multiple_scopes_per_mutation=False,
        batch_across_scopes=False,
    )


def _scope_key(scope: Mapping[str, JsonValue]) -> str:
    items = tuple(sorted((str(k), repr(v)) for k, v in scope.items()))
    return repr(items)


@dataclass
class FakeDestination:
    """In-memory destination used for contract and apply tests."""

    manifest: DestinationManifest
    fail_names: set[str] = field(default_factory=set)
    fail_batch: bool = False
    last_request: ApplyDestinationRequest | None = None
    # scope_key -> secret names (for prune-capable fakes)
    remote_names: dict[str, set[str]] = field(default_factory=dict)

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        del config
        return []

    async def list_names(
        self,
        config: Mapping[str, JsonValue],
        scope: Mapping[str, JsonValue],
        context: OperationContext,
    ) -> frozenset[str]:
        del config
        if not self.manifest.capabilities.list_names:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Fake connector does not support list_names",
                    correlation_id=context.correlation_id,
                )
            )
        return frozenset(self.remote_names.get(_scope_key(scope), set()))

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        del context
        self.last_request = request
        put_outcome = (
            self._apply_batch(request)
            if self.manifest.capabilities.put_batch.supported
            else self._apply_individual(request)
        )
        delete_outcome = self._apply_deletes(request.deletes)
        return ApplyDestinationResult(
            results=put_outcome.results + delete_outcome.results,
            requests_made=put_outcome.requests_made + delete_outcome.requests_made,
        )

    def _apply_deletes(self, deletes: list[DeleteMutation]) -> ApplyDestinationResult:
        if not deletes:
            return ApplyDestinationResult(results=(), requests_made=0)
        if not self.manifest.capabilities.delete_batch.supported:
            error = SafeConnectorError(
                code="DESTINATION_INVALID",
                message="Fake connector does not support deletes",
            )
            return ApplyDestinationResult(
                results=tuple(
                    MutationResult(mutation_id=d.mutation_id, status="failed", error=error)
                    for d in deletes
                ),
                requests_made=0,
            )
        results: list[MutationResult] = []
        for deletion in deletes:
            key = _scope_key(dict(deletion.scopes[0])) if deletion.scopes else ""
            names = self.remote_names.setdefault(key, set())
            names.discard(deletion.name)
            results.append(
                MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="applied",
                    effect="deleted",
                )
            )
        return ApplyDestinationResult(results=tuple(results), requests_made=len(deletes))

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
                if mutation.scopes:
                    key = _scope_key(dict(mutation.scopes[0]))
                    self.remote_names.setdefault(key, set()).add(mutation.name)
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
                if mutation.scopes:
                    key = _scope_key(dict(mutation.scopes[0]))
                    self.remote_names.setdefault(key, set()).add(mutation.name)
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


@dataclass
class FakePruneFactory:
    """Fake with list_names + delete for reconcile tests."""

    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="fake-prune",
            version="0.1.0",
            capabilities=_prune_capabilities(),
        )
    )
    remote_names: dict[str, set[str]] = field(default_factory=dict)

    def create(self, services: Any) -> FakeDestination:
        del services
        # Share the same dict so tests can seed inventory before plan/apply.
        return FakeDestination(manifest=self.manifest, remote_names=self.remote_names)


def builtin_fake_factories() -> tuple[FakeIndividualFactory, FakeBatchFactory, FakePruneFactory]:
    return (FakeIndividualFactory(), FakeBatchFactory(), FakePruneFactory())
