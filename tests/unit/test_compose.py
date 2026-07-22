from __future__ import annotations

from secretsync.application.services import create_services
from secretsync.config.compose import compose_from_config
from secretsync.config.loader import ConfigLoader
from secretsync.domain.errors import ConfigInvalidError
from tests.conftest import FULL_ENV, fixture_path


def test_compose_inheritance_and_order() -> None:
    config = ConfigLoader().load(fixture_path("valid_full.yaml"))
    composed = compose_from_config(config)
    production = composed["production"]
    assert production.order == ("databaseUrl", "sentryDsn", "stripeSecretKey")
    assert production.require("databaseUrl").env_name == "YB_DATABASE_URL"
    staging = composed["staging"]
    assert staging.require("databaseUrl").env_name == "YB_STAGING_DATABASE_URL"


def test_compose_cycle_rejected() -> None:
    config = ConfigLoader().load(fixture_path("cycle.yaml"))
    try:
        compose_from_config(config)
        raise AssertionError("expected ConfigInvalidError")
    except ConfigInvalidError as exc:
        assert exc.code == "CONFIG_INVALID"
        assert "cycle" in exc.safe.message.lower()


def test_override_only_available_members() -> None:
    config = ConfigLoader().load(fixture_path("bad_override.yaml"))
    try:
        compose_from_config(config)
        raise AssertionError("expected ConfigInvalidError")
    except ConfigInvalidError as exc:
        assert "notIncluded" in exc.safe.message


def test_override_allow_empty() -> None:
    config = ConfigLoader().load(fixture_path("override_staging.yaml"))
    composed = compose_from_config(config)
    ref = composed["staging"].require("databaseUrl")
    assert ref.env_name == "YB_STAGING_DATABASE_URL"
    assert ref.allow_empty is True


def test_unknown_keys_rejected() -> None:
    services = create_services(FULL_ENV)
    try:
        services.config_loader.load_text(
            """
version: 1
changeDetection: always-write
unexpected: true
secrets:
  a:
    env: A_ENV
sets:
  s:
    include: [a]
destinations:
  github:
    connector: github-actions
    auth:
      tokenEnv: GITHUB_TOKEN
deployments:
  - name: d1
    set: s
    destination: github
    scope: {}
    secrets:
      a: A
""",
            source="inline",
        )
        raise AssertionError("expected ConfigInvalidError")
    except ConfigInvalidError as exc:
        assert exc.code == "CONFIG_INVALID"
