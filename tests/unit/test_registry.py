from __future__ import annotations

from dataclasses import replace

import pytest

from secretsync.destinations.base import DestinationManifest
from secretsync.destinations.fake import FakeIndividualFactory, builtin_fake_factories
from secretsync.destinations.registry import (
    KNOWN_CONNECTOR_IDS,
    PLANNED_CONNECTOR_IDS,
    ConnectorRegistry,
)
from secretsync.domain.errors import ConnectorNotImplementedError, UnknownConnectorError


def test_known_alias_matches_planned() -> None:
    assert KNOWN_CONNECTOR_IDS is PLANNED_CONNECTOR_IDS
    assert "github-actions" in PLANNED_CONNECTOR_IDS


def test_empty_registry_planned_and_unknown() -> None:
    registry = ConnectorRegistry()
    assert registry.known_ids() == sorted(PLANNED_CONNECTOR_IDS)
    assert registry.is_known("vercel")
    assert not registry.is_registered("vercel")
    assert not registry.is_known("nope")

    with pytest.raises(ConnectorNotImplementedError) as planned:
        registry.create("sst", services=None)
    assert planned.value.code == "CONFIG_INVALID"
    assert "sst" in planned.value.safe.message

    with pytest.raises(UnknownConnectorError) as unknown:
        registry.create("totally-unknown", services=None)
    assert "totally-unknown" in unknown.value.safe.message

    manifests = registry.list_manifests()
    assert all(m["status"] == "planned" for m in manifests)
    assert {m["id"] for m in manifests} == set(PLANNED_CONNECTOR_IDS)
    assert all(m["version"] == "0.0.0-planned" for m in manifests)


def test_registry_with_fakes_create_and_list() -> None:
    registry = ConnectorRegistry(builtin_fake_factories())
    assert registry.is_registered("fake-individual")
    assert registry.is_registered("fake-batch")
    assert registry.is_known("fake-individual")
    assert registry.is_known("github-actions")

    dest = registry.create("fake-individual", services=object())
    assert dest.manifest.id == "fake-individual"

    manifests = registry.list_manifests()
    by_id = {m["id"]: m for m in manifests}
    assert by_id["fake-batch"]["status"] == "registered"
    assert by_id["fake-individual"]["version"] == "0.1.0"
    assert by_id["github-actions"]["status"] == "planned"
    assert by_id["vercel"]["status"] == "planned"
    assert by_id["sst"]["status"] == "planned"
    statuses = [m["status"] for m in manifests]
    assert statuses == [
        "registered",
        "registered",
        "registered",
        "planned",
        "planned",
        "planned",
    ]
    assert by_id["fake-prune"]["status"] == "registered"


def test_registered_planned_id_skips_planned_list_entry() -> None:
    """If a planned id is also registered, list_manifests must not duplicate it as planned."""
    base = FakeIndividualFactory()
    factory = replace(
        base,
        manifest=DestinationManifest(
            id="github-actions",
            version="9.9.9",
            capabilities=base.manifest.capabilities,
        ),
    )
    registry = ConnectorRegistry((factory,))
    assert registry.is_registered("github-actions")
    manifests = registry.list_manifests()
    gh = [m for m in manifests if m["id"] == "github-actions"]
    assert len(gh) == 1
    assert gh[0]["status"] == "registered"
    assert gh[0]["version"] == "9.9.9"
