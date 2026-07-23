from __future__ import annotations

import pytest

from secretsync.application.plan import build_plan, build_plan_async, plan_from_path
from secretsync.application.services import create_services
from secretsync.application.validate import validate_config
from secretsync.config.compose import compose_from_config
from secretsync.config.loader import ConfigLoader
from secretsync.destinations.base import OperationContext
from secretsync.destinations.fake import FakePruneFactory, _scope_key
from secretsync.destinations.sst import parse_sst_secret_list_names
from tests.conftest import fixture_path

PRUNE_ENV = {
    "YB_DATABASE_URL": "postgres://x",
    "STRIPE_SECRET_KEY": "sk_test",
}


@pytest.mark.asyncio
async def test_prune_plans_orphan_deletes() -> None:
    services = create_services(PRUNE_ENV)
    config = ConfigLoader().load(fixture_path("fake_prune.yaml"))
    composed = compose_from_config(config)
    factory = services.connectors._factories["fake-prune"]
    assert isinstance(factory, FakePruneFactory)
    scope = {"stage": "production"}
    factory.remote_names[_scope_key(scope)] = {
        "DATABASE_URL",
        "STRIPE_SECRET_KEY",
        "ORPHAN_SECRET",
    }

    plan = await build_plan_async(services, config, composed, prune=True)
    assert len(plan.puts) == 2
    assert len(plan.deletes) == 1
    assert plan.deletes[0].target.name == "ORPHAN_SECRET"
    assert "ORPHAN_SECRET" not in {p.target.name for p in plan.puts}


@pytest.mark.asyncio
async def test_without_prune_no_deletes_and_no_list() -> None:
    services = create_services(PRUNE_ENV)
    config = ConfigLoader().load(fixture_path("fake_prune.yaml"))
    composed = compose_from_config(config)
    plan = await build_plan_async(services, config, composed, prune=False)
    assert len(plan.deletes) == 0
    assert len(plan.puts) == 2


@pytest.mark.asyncio
async def test_prune_no_orphan_when_remote_matches() -> None:
    services = create_services(PRUNE_ENV)
    config = ConfigLoader().load(fixture_path("fake_prune.yaml"))
    composed = compose_from_config(config)
    factory = services.connectors._factories["fake-prune"]
    assert isinstance(factory, FakePruneFactory)
    scope = {"stage": "production"}
    factory.remote_names[_scope_key(scope)] = {"DATABASE_URL", "STRIPE_SECRET_KEY"}
    plan = await build_plan_async(services, config, composed, prune=True)
    assert plan.deletes == ()


def test_sync_plan_from_path_without_prune() -> None:
    services = create_services(PRUNE_ENV)
    plan, result = plan_from_path(services, fixture_path("fake_prune.yaml"), prune=False)
    assert result.ok
    assert plan is not None
    assert plan.deletes == ()


@pytest.mark.asyncio
async def test_prune_unsupported_connector_fails() -> None:
    services = create_services(
        {
            "YB_DATABASE_URL": "x",
            "STRIPE_SECRET_KEY": "y",
            "API_TOKEN": "z",
        }
    )
    # fake_apply.yaml uses fake-batch / fake-individual (no list/delete).
    config = ConfigLoader().load(fixture_path("fake_apply.yaml"))
    composed = compose_from_config(config)
    with pytest.raises(Exception) as excinfo:
        await build_plan_async(services, config, composed, prune=True)
    assert "does not support prune" in str(excinfo.value)


@pytest.mark.asyncio
async def test_fake_prune_apply_deletes() -> None:
    dest = FakePruneFactory().create(None)
    scope = {"stage": "production"}
    key = _scope_key(scope)
    dest.remote_names[key] = {"KEEP", "DROP"}
    from secretsync.destinations.base import (
        ApplyDestinationRequest,
        DeleteMutation,
        PutMutation,
    )

    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="d",
            destination_config={},
            mutations=[
                PutMutation(
                    mutation_id="d:KEEP",
                    name="KEEP",
                    value=bytearray(b"v"),
                    scopes=(scope,),
                )
            ],
            deletes=[
                DeleteMutation(
                    mutation_id="d:delete:DROP",
                    name="DROP",
                    scopes=(scope,),
                )
            ],
        ),
        OperationContext(correlation_id="c"),
    )
    assert {r.mutation_id: r.effect for r in result.results} == {
        "d:KEEP": "upserted",
        "d:delete:DROP": "deleted",
    }
    assert dest.remote_names[key] == {"KEEP"}


def test_parse_sst_secret_list_names_dotenv_and_table() -> None:
    dotenv = b'FOO="bar"\nBAZ=qux\n# comment\n'
    assert parse_sst_secret_list_names(dotenv) == frozenset({"FOO", "BAZ"})
    table = b"Name\nALPHA\nBETA value-here\n"
    assert "ALPHA" in parse_sst_secret_list_names(table)
    assert "BETA" in parse_sst_secret_list_names(table)


def test_build_plan_still_sync_put_only() -> None:
    config = ConfigLoader().load(fixture_path("fake_prune.yaml"))
    composed = compose_from_config(config)
    plan = build_plan(config, composed)
    assert plan.deletes == ()
    assert len(plan.puts) == 2


def test_validate_fake_prune_config() -> None:
    services = create_services(PRUNE_ENV)
    result = validate_config(services, fixture_path("fake_prune.yaml"))
    assert result.ok
