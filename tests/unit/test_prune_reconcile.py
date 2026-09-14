from __future__ import annotations

from pathlib import Path

import pytest

from secretsync.application.apply import run_clear
from secretsync.application.plan import (
    _inventory_units,
    build_clear_plan_async,
    build_plan,
    build_plan_async,
    plan_from_path,
)
from secretsync.application.services import create_services
from secretsync.application.validate import validate_config
from secretsync.config.compose import compose_from_config
from secretsync.config.loader import ConfigLoader
from secretsync.destinations.base import OperationContext
from secretsync.destinations.fake import FakePruneFactory, _scope_key
from secretsync.destinations.sst import (
    SstFactory,
    parse_sst_secret_list_names,
    parse_sst_secret_list_sections,
)
from secretsync.domain.models import ValueKind
from secretsync.infrastructure.process import AsyncSecureProcessRunner, ProcessResult
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
async def test_clear_plans_all_remote_deletes() -> None:
    services = create_services({})  # no source secrets required
    config = ConfigLoader().load(fixture_path("fake_prune.yaml"))
    factory = services.connectors._factories["fake-prune"]
    assert isinstance(factory, FakePruneFactory)
    scope = {"stage": "production"}
    factory.remote_names[_scope_key(scope)] = {
        "DATABASE_URL",
        "STRIPE_SECRET_KEY",
        "ORPHAN_SECRET",
    }

    plan = await build_clear_plan_async(services, config)
    assert plan.puts == ()
    assert {d.target.name for d in plan.deletes} == {
        "DATABASE_URL",
        "STRIPE_SECRET_KEY",
        "ORPHAN_SECRET",
    }


def test_clear_skips_source_env_check() -> None:
    services = create_services({})
    result = validate_config(
        services,
        fixture_path("fake_prune.yaml"),
        require_sources=False,
    )
    assert result.ok


def test_run_clear_declined() -> None:
    services = create_services({})
    factory = services.connectors._factories["fake-prune"]
    assert isinstance(factory, FakePruneFactory)
    scope = {"stage": "production"}
    factory.remote_names[_scope_key(scope)] = {"DATABASE_URL", "ORPHAN"}
    report = run_clear(
        services,
        config_path=fixture_path("fake_prune.yaml"),
        max_concurrency=2,
        confirm_fn=lambda _prompt: False,
    )
    assert report.exit_code == 0
    assert report.summary.applied == 0
    assert report.destinations == ()
    assert factory.remote_names[_scope_key(scope)] == {"DATABASE_URL", "ORPHAN"}


def test_run_clear_applies_deletes() -> None:
    services = create_services({})
    factory = services.connectors._factories["fake-prune"]
    assert isinstance(factory, FakePruneFactory)
    scope = {"stage": "production"}
    factory.remote_names[_scope_key(scope)] = {"DATABASE_URL", "ORPHAN"}
    report = run_clear(
        services,
        config_path=fixture_path("fake_prune.yaml"),
        max_concurrency=2,
        confirm_fn=lambda _prompt: True,
    )
    assert report.exit_code == 0
    assert report.summary.applied == 2
    assert report.summary.failed == 0
    assert factory.remote_names[_scope_key(scope)] == set()


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


def test_parse_sst_secret_list_sections_fallback_vs_stage() -> None:
    stdout = b"""# fallback
TEST_SECRET=meow

# yellowbrick/staging
STRIPE_API_KEY=meow
DISCORD_BOT_TOKEN=meow
YB_DATABASE_URL=meow
"""
    stage, fallback = parse_sst_secret_list_sections(stdout)
    assert fallback == frozenset({"TEST_SECRET"})
    assert stage == frozenset(
        {"STRIPE_API_KEY", "DISCORD_BOT_TOKEN", "YB_DATABASE_URL"}
    )
    assert parse_sst_secret_list_names(stdout) == stage | fallback


def test_parse_sst_secret_list_sections_flat_is_stage() -> None:
    stage, fallback = parse_sst_secret_list_sections(b'FOO="bar"\nBAZ=qux\n')
    assert stage == frozenset({"FOO", "BAZ"})
    assert fallback == frozenset()


def test_inventory_units_synthesizes_sst_fallback_for_prune() -> None:
    """Stage-only SST YAML still gets a fallback inventory unit (empty intended)."""
    config = ConfigLoader().load(fixture_path("valid_full.yaml"))
    selected = [d for d in config.deployments if d.destination == "sst"]
    assert selected
    units = _inventory_units(config, selected)
    fallback_units = [
        u
        for u in units
        if u.destination_id == "sst"
        and u.kind is ValueKind.SECRET
        and bool(u.scope.get("fallback"))
    ]
    assert len(fallback_units) == 1
    assert fallback_units[0].intended_names == frozenset()
    assert fallback_units[0].scope.get("stage") == "production"


@pytest.mark.asyncio
async def test_prune_plans_sst_fallback_orphan_deletes(tmp_path: Path) -> None:
    """Orphaned fallback secrets are planned for delete with fallback: true scope."""

    class _ListRunner(AsyncSecureProcessRunner):
        async def execute(self, request):  # type: ignore[no-untyped-def]
            args = list(request.arguments)
            if "list" in args and "--fallback" in args:
                stdout = b"# fallback\nTEST_SECRET=meow\n"
            elif "list" in args:
                stdout = b"# app/production\nDatabaseUrl=x\nStripeSecretKey=y\n"
            else:
                stdout = b""
            return ProcessResult(
                exit_code=0,
                duration_ms=1,
                stdout_bytes=stdout,
                stderr_summary="",
            )

    cfg_path = tmp_path / "secretsync.yaml"
    cfg_path.write_text(
        f"""
version: 1
changeDetection: always-write
secrets:
  databaseUrl:
    env: YB_DATABASE_URL
  stripeSecretKey:
    env: STRIPE_SECRET_KEY
sets:
  production:
    include: [databaseUrl, stripeSecretKey]
destinations:
  sst:
    connector: sst
    workingDirectory: "{tmp_path.as_posix()}"
    executable: sst
deployments:
  - name: sst-production
    set: production
    destination: sst
    scope:
      stage: production
      fallback: false
    secrets:
      databaseUrl: DatabaseUrl
      stripeSecretKey: StripeSecretKey
""",
        encoding="utf-8",
    )

    services = create_services(PRUNE_ENV)
    original = SstFactory.create

    def _create(self, services_arg):  # type: ignore[no-untyped-def]
        dest = original(self, services_arg)
        dest.process_runner = _ListRunner()
        dest._resolved_executable = Path("/usr/bin/true")
        dest._argv_prefix = ()
        dest._probe_ok = False
        return dest

    SstFactory.create = _create  # type: ignore[method-assign]
    try:
        config = ConfigLoader().load(cfg_path)
        composed = compose_from_config(config)
        plan = await build_plan_async(services, config, composed, prune=True)
    finally:
        SstFactory.create = original  # type: ignore[method-assign]

    fallback_deletes = [
        d for d in plan.deletes if d.target.scope.get("fallback") is True
    ]
    assert len(fallback_deletes) == 1
    assert fallback_deletes[0].target.name == "TEST_SECRET"
    assert fallback_deletes[0].target.scope.get("fallback") is True


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
