from __future__ import annotations

import pytest

from secretsync.destinations.base import (
    ApplyDestinationRequest,
    OperationContext,
    PutMutation,
)
from secretsync.destinations.fake import FakeBatchFactory, FakeIndividualFactory


def _mutations(n: int) -> list[PutMutation]:
    return [
        PutMutation(
            mutation_id=f"dep:NAME_{i}",
            name=f"NAME_{i}",
            value=bytearray(f"value-{i}".encode()),
            scopes=({"env": "test"},),
        )
        for i in range(n)
    ]


@pytest.mark.asyncio
async def test_fake_individual_one_request_per_mutation() -> None:
    destination = FakeIndividualFactory().create(services=None)
    request = ApplyDestinationRequest(
        deployment_id="dep",
        destination_config={"connector": "fake-individual"},
        mutations=_mutations(5),
    )
    result = await destination.apply(request, OperationContext(correlation_id="c1"))
    assert result.requests_made == 5
    assert len(result.results) == 5
    assert all(r.status == "applied" for r in result.results)
    assert destination.manifest.capabilities.put_batch.supported is False


@pytest.mark.asyncio
async def test_fake_batch_single_request_for_group() -> None:
    destination = FakeBatchFactory(max_items=100).create(services=None)
    request = ApplyDestinationRequest(
        deployment_id="dep",
        destination_config={"connector": "fake-batch"},
        mutations=_mutations(5),
    )
    result = await destination.apply(request, OperationContext(correlation_id="c1"))
    assert result.requests_made == 1
    assert len(result.results) == 5
    assert all(r.status == "applied" and r.effect == "upserted" for r in result.results)
    assert destination.manifest.capabilities.put_batch.supported is True


@pytest.mark.asyncio
async def test_fake_batch_chunks_by_max_items() -> None:
    destination = FakeBatchFactory(max_items=2).create(services=None)
    request = ApplyDestinationRequest(
        deployment_id="dep",
        destination_config={"connector": "fake-batch"},
        mutations=_mutations(5),
    )
    result = await destination.apply(request, OperationContext(correlation_id="c1"))
    assert result.requests_made == 3
    assert len(result.results) == 5


@pytest.mark.asyncio
async def test_core_passes_full_mutation_list_unchanged() -> None:
    """Batching independence: connector receives the full list; core does not pre-split."""
    destination = FakeBatchFactory().create(services=None)
    mutations = _mutations(4)
    request = ApplyDestinationRequest(
        deployment_id="dep",
        destination_config={},
        mutations=mutations,
    )
    await destination.apply(request, OperationContext(correlation_id="c1"))
    assert destination.last_request is not None
    assert len(destination.last_request.mutations) == 4
    assert [m.mutation_id for m in destination.last_request.mutations] == [
        m.mutation_id for m in mutations
    ]


@pytest.mark.asyncio
async def test_batch_failure_marks_all_members() -> None:
    destination = FakeBatchFactory().create(services=None)
    destination.fail_batch = True
    request = ApplyDestinationRequest(
        deployment_id="dep",
        destination_config={},
        mutations=_mutations(3),
    )
    result = await destination.apply(request, OperationContext(correlation_id="c1"))
    assert result.requests_made == 1
    assert all(r.status == "failed" for r in result.results)
