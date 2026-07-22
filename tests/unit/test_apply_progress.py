from __future__ import annotations

from secretsync.application.apply import DestinationProgress, run_apply
from secretsync.application.services import create_services
from tests.conftest import fixture_path

FAKE_ENV = {
    "YB_DATABASE_URL": "SECRET_CANARY_a9f731",
    "STRIPE_SECRET_KEY": "sk_live_canary",
    "API_TOKEN": "token_canary",
}


def test_destination_progress_callback() -> None:
    events: list[DestinationProgress] = []
    services = create_services(FAKE_ENV)
    report = run_apply(
        services,
        config_path=fixture_path("fake_apply.yaml"),
        confirm=False,
        max_concurrency=2,
        on_destination_progress=events.append,
    )
    assert report.exit_code == 0
    assert events
    phases = {(e.destination_id, e.phase) for e in events}
    assert ("batchSink", "started") in phases
    assert ("batchSink", "finished") in phases
    assert ("individualSink", "started") in phases
    assert ("individualSink", "finished") in phases
    for event in events:
        assert "SECRET_CANARY" not in event.destination_id
        assert "SECRET_CANARY" not in event.connector


def test_mutation_ids_filter_applies_subset() -> None:
    services = create_services(FAKE_ENV)
    full = run_apply(
        services,
        config_path=fixture_path("fake_apply.yaml"),
        confirm=False,
        max_concurrency=2,
    )
    assert full.summary.applied == 4
    one_id = next(
        result.mutation_id
        for block in full.destinations
        for result in block.results
        if block.id == "batchSink"
    )
    filtered = run_apply(
        services,
        config_path=fixture_path("fake_apply.yaml"),
        confirm=False,
        max_concurrency=2,
        mutation_ids=frozenset({one_id}),
    )
    assert filtered.exit_code == 0
    assert filtered.summary.applied == 1
    assert filtered.summary.failed == 0
    assert len(filtered.destinations) == 1
    assert filtered.destinations[0].id == "batchSink"
