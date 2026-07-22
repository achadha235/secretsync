from __future__ import annotations

from secretsync.application.plan import build_plan, plan_from_path
from secretsync.application.services import create_services
from secretsync.application.validate import validate_config
from secretsync.config.compose import compose_from_config
from secretsync.config.loader import ConfigLoader
from tests.conftest import FULL_ENV, fixture_path


def test_validate_full_config() -> None:
    services = create_services(FULL_ENV)
    result = validate_config(services, fixture_path("valid_full.yaml"))
    assert result.ok
    assert result.exit_code == 0


def test_keyed_fingerprint_unimplemented() -> None:
    services = create_services({"A_ENV": "x", "GITHUB_TOKEN": "t"})
    result = validate_config(services, fixture_path("keyed_fingerprint.yaml"))
    assert not result.ok
    assert result.exit_code == 2
    assert result.issues[0].code == "UNIMPLEMENTED_CHANGE_DETECTION"


def test_unknown_secret_in_deployment() -> None:
    services = create_services({"A_ENV": "x", "GITHUB_TOKEN": "t"})
    result = validate_config(services, fixture_path("unknown_secret.yaml"))
    assert not result.ok
    assert result.issues[0].code == "CONFIG_INVALID"


def test_duplicate_target_rejected() -> None:
    services = create_services({"A_ENV": "x", "B_ENV": "y", "GITHUB_TOKEN": "t"})
    result = validate_config(services, fixture_path("duplicate_target.yaml"))
    assert not result.ok
    assert "Duplicate target" in result.issues[0].message


def test_missing_source_env() -> None:
    env = {k: v for k, v in FULL_ENV.items() if k != "STRIPE_SECRET_KEY"}
    services = create_services(env)
    result = validate_config(services, fixture_path("valid_full.yaml"))
    assert not result.ok
    assert result.exit_code == 3
    assert result.issues[0].code == "SOURCE_MISSING"


def test_missing_auth_env() -> None:
    env = {k: v for k, v in FULL_ENV.items() if k != "GITHUB_TOKEN"}
    services = create_services(env)
    result = validate_config(services, fixture_path("valid_full.yaml"))
    assert not result.ok
    assert result.exit_code == 3
    assert result.issues[0].code == "AUTH_MISSING"


def test_unknown_connector() -> None:
    services = create_services({"A_ENV": "x", "TOKEN_ENV": "t"})
    result = validate_config(services, fixture_path("unknown_connector.yaml"))
    assert not result.ok
    assert "unknown connector" in result.issues[0].message.lower()


def test_build_plan_explicit_publish_only() -> None:
    config = ConfigLoader().load(fixture_path("explicit_publish.yaml"))
    composed = compose_from_config(config)
    # unpublished is in the set but must not be required for validate of published-only
    plan = build_plan(config, composed)
    assert len(plan.puts) == 1
    assert plan.puts[0].source.logical_id == "published"
    assert plan.puts[0].target.name == "PUBLISHED"
    assert plan.strategy == "always-write"


def test_plan_from_path_full() -> None:
    services = create_services(FULL_ENV)
    plan, result = plan_from_path(services, fixture_path("valid_full.yaml"))
    assert result.ok
    assert plan is not None
    assert plan.strategy == "always-write"
    # github: 2, vercel: 3, sst: 2
    assert len(plan.puts) == 7
    ids = {p.mutation_id for p in plan.puts}
    assert "github-production:DATABASE_URL" in ids
    assert "vercel-production:NEXT_PUBLIC_SENTRY_DSN" in ids
    # sentryDsn is in production set but not published to github
    github_logical = {
        p.source.logical_id for p in plan.puts if p.deployment_id == "github-production"
    }
    assert "sentryDsn" not in github_logical


def test_plan_contains_no_secret_values() -> None:
    services = create_services(FULL_ENV)
    plan, _ = plan_from_path(services, fixture_path("valid_full.yaml"))
    assert plan is not None
    rendered = repr(plan)
    for value in FULL_ENV.values():
        assert value not in rendered
