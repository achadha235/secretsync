from __future__ import annotations

import json

from click.testing import CliRunner

from secretsync.application.plan import plan_from_path
from secretsync.application.services import create_services
from secretsync.cli import cli
from secretsync.presentation.json import plan_to_dict
from tests.conftest import FULL_ENV, fixture_path


def test_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "validate" in result.output
    assert "plan" in result.output


def test_validate_cli_ok() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("valid_full.yaml")), "validate"],
        env=FULL_ENV,
    )
    assert result.exit_code == 0
    assert "valid" in result.output.lower()


def test_validate_cli_missing_env() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("valid_full.yaml")), "validate"],
        env={"PATH": "/usr/bin"},
    )
    assert result.exit_code == 3
    assert "SOURCE_MISSING" in result.output or "absent" in result.output.lower()


def test_plan_cli_json() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--config",
            str(fixture_path("valid_full.yaml")),
            "--format",
            "json",
            "plan",
        ],
        env=FULL_ENV,
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["schemaVersion"] == 1
    assert payload["strategy"] == "always-write"
    assert payload["summary"]["puts"] == 7
    for value in ("postgres://prod", "sk_test", "ghp_test"):
        assert value not in result.output


def test_plan_json_schema_no_values() -> None:
    services = create_services(FULL_ENV)
    plan, result = plan_from_path(services, fixture_path("valid_full.yaml"))
    assert result.ok and plan is not None
    serialized = json.dumps(plan_to_dict(plan))
    for value in FULL_ENV.values():
        assert value not in serialized


def test_apply_stub() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["apply", "--yes"], env=FULL_ENV)
    assert result.exit_code == 2
    combined = result.output + (result.stderr or "")
    assert "M2" in combined


def test_ui_stub() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["ui"])
    assert result.exit_code == 2


def test_connectors_list() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["connectors"])
    assert result.exit_code == 0
    assert "github-actions" in result.output
    assert "vercel" in result.output
    assert "sst" in result.output


def test_keyed_fingerprint_cli() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("keyed_fingerprint.yaml")), "validate"],
        env={"A_ENV": "x", "GITHUB_TOKEN": "t"},
    )
    assert result.exit_code == 2
    assert "UNIMPLEMENTED_CHANGE_DETECTION" in result.output
