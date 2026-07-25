from __future__ import annotations

import json
from importlib.metadata import version

from click.testing import CliRunner

from secretsync.cli import cli
from tests.conftest import FULL_ENV, fixture_path

FAKE_ENV = {
    "YB_DATABASE_URL": "SECRET_CANARY_a9f731",
    "STRIPE_SECRET_KEY": "sk_live_canary",
    "API_TOKEN": "token_canary",
}


def test_help() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    assert "validate" in result.output
    assert "plan" in result.output
    assert "clear" in result.output


def test_clear_cli_requires_exact_phrase() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("fake_prune.yaml")), "clear"],
        input="nope\n",
        env={},
    )
    assert result.exit_code == 0
    assert "confirm clear operation" in result.output


def test_clear_cli_with_phrase() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("fake_prune.yaml")), "clear"],
        input="confirm clear operation\n",
        env={},
    )
    assert result.exit_code == 0
    assert "applied=0" in result.output


def test_version() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0
    assert result.output == f"{version('secretsync-cli')}\n"


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
    cleared = {
        "PATH": "/usr/bin",
        "YB_DATABASE_URL": None,
        "YB_STAGING_DATABASE_URL": None,
        "STRIPE_SECRET_KEY": None,
        "SENTRY_DSN": None,
        "GITHUB_TOKEN": None,
        "VERCEL_TOKEN": None,
    }
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("valid_full.yaml")), "validate"],
        env=cleared,
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
    payload = json.loads(result.stdout)
    assert payload["schemaVersion"] == 1
    assert payload["strategy"] == "always-write"
    assert payload["summary"]["puts"] == 7
    for value in ("postgres://prod", "sk_test", "ghp_test"):
        assert value not in result.stdout


def test_apply_cli_with_fakes() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--config",
            str(fixture_path("fake_apply.yaml")),
            "--format",
            "json",
            "apply",
            "--yes",
        ],
        env=FAKE_ENV,
    )
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["applied"] == 4
    assert payload["summary"]["failed"] == 0
    for value in FAKE_ENV.values():
        assert value not in result.stdout


def test_ui_json_format_rejected() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["--format", "json", "ui"])
    assert result.exit_code == 2
    assert "bypasses Textual" in result.output or "bypasses Textual" in (result.stderr or "")


def test_ui_help_lists_command() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["ui", "--help"])
    assert result.exit_code == 0
    assert "Textual" in result.output


def test_connectors_list() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["connectors"])
    assert result.exit_code == 0
    assert "fake-batch" in result.output
    assert "fake-individual" in result.output
    assert "github-actions" in result.output
    assert "vercel" in result.output
    assert "sst" in result.output
    assert result.output.count("[registered]") >= 5
    assert "[planned]" not in result.output


def test_keyed_fingerprint_cli() -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["--config", str(fixture_path("keyed_fingerprint.yaml")), "validate"],
        env={"A_ENV": "x", "GITHUB_TOKEN": "t"},
    )
    assert result.exit_code == 2
    assert "UNIMPLEMENTED_CHANGE_DETECTION" in result.output
