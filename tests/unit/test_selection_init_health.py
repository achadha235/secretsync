from __future__ import annotations

from click.testing import CliRunner

from secretsync.application.plan import plan_from_path
from secretsync.application.services import create_services
from secretsync.application.validate import validate_config
from secretsync.cli import cli
from tests.conftest import fixture_path


def test_selection_staging_skips_prod_env() -> None:
    env = {"STAGING_ONLY_SECRET": "s"}
    services = create_services(env)
    path = fixture_path("selection_two_env.yaml")
    full = validate_config(services, path)
    assert full.exit_code == 3  # missing PROD_ONLY_SECRET
    staging = validate_config(services, path, deployments={"staging-deploy"})
    assert staging.ok
    plan, result = plan_from_path(services, path, deployments={"staging-deploy"})
    assert result.ok and plan is not None
    assert len(plan.puts) == 1
    assert plan.puts[0].deployment_id == "staging-deploy"


def test_cli_init_and_second_fails(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    first = runner.invoke(cli, ["init"])
    assert first.exit_code == 0
    assert (tmp_path / "secretsync.yaml").is_file()
    assert (tmp_path / ".env.secretsync.tpl").is_file()
    assert (tmp_path / ".secretsync" / "audit.log").is_file()
    second = runner.invoke(cli, ["init"])
    assert second.exit_code == 2


def test_cli_health_skips_unset(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["health"],
        env={
            "PATH": "/usr/bin:/bin",
            "GITHUB_TOKEN": None,
            "VERCEL_TOKEN": None,
            "AWS_PROFILE": None,
            "AWS_ACCESS_KEY_ID": None,
            "AWS_SECRET_ACCESS_KEY": None,
        },
    )
    assert result.exit_code == 0
    assert "GITHUB_TOKEN not set" in result.stdout
    assert "VERCEL_TOKEN not set" in result.stdout
    assert "skipping check for SST" in result.stdout or "AWS_PROFILE" in result.stdout
