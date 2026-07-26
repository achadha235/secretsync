from __future__ import annotations

import json

import httpx
import pytest
import respx
from click.testing import CliRunner

from secretsync.application.apply import run_apply, sanitize_exception
from secretsync.application.plan import plan_from_path
from secretsync.application.services import create_services
from secretsync.cli import cli
from secretsync.presentation.json import render_apply_json, render_plan_json
from tests.conftest import fixture_path
from tests.security.conftest import CANARY, FAKE_ENV, assert_canary_absent, assert_no_canary_under


@pytest.mark.security
def test_canary_apply_cli_human_json(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
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
    assert_canary_absent(result.stdout, label="json stdout")
    assert_canary_absent(result.stderr or "", label="json stderr")
    payload = json.loads(result.stdout)
    assert payload["summary"]["applied"] == 4
    assert_no_canary_under(tmp_path)

    human = runner.invoke(
        cli,
        ["--config", str(fixture_path("fake_apply.yaml")), "apply", "--yes"],
        env=FAKE_ENV,
    )
    assert human.exit_code == 0
    assert_canary_absent(human.stdout, label="human stdout")
    assert_canary_absent(human.stderr or "", label="human stderr")


@pytest.mark.security
def test_canary_apply_failure_paths(tmp_path) -> None:
    from secretsync.application.services import AppServices, SystemClock
    from secretsync.config.loader import ConfigLoader
    from secretsync.destinations.fake import FakeIndividualFactory
    from secretsync.destinations.registry import ConnectorRegistry
    from secretsync.infrastructure.http import HttpClientFactory
    from secretsync.infrastructure.process import AsyncSecureProcessRunner
    from secretsync.sources.environment import EnvironmentSource

    class FailingFactory(FakeIndividualFactory):
        def create(self, services: object) -> object:
            dest = super().create(services)
            dest.fail_names = {"FAIL_ME"}
            return dest

    environ = {"YB_DATABASE_URL": CANARY}
    services = AppServices(
        config_loader=ConfigLoader(),
        source=EnvironmentSource(environ),
        connectors=ConnectorRegistry((FailingFactory(),)),
        environ=environ,
        clock=SystemClock(),
        http_client_factory=HttpClientFactory(),
        process_runner=AsyncSecureProcessRunner(),
    )
    report = run_apply(
        services,
        config_path=fixture_path("fake_apply_fail.yaml"),
        confirm=False,
        max_concurrency=1,
    )
    assert report.summary.failed >= 1
    blob = render_apply_json(report)
    assert_canary_absent(blob, label="fail report json")
    assert CANARY not in repr(report)
    assert_no_canary_under(tmp_path)


@pytest.mark.security
def test_canary_plan_and_exceptions() -> None:
    services = create_services(FAKE_ENV)
    plan, _ = plan_from_path(services, fixture_path("fake_apply.yaml"))
    assert plan is not None
    assert_canary_absent(render_plan_json(plan), label="plan json")
    assert CANARY not in repr(plan)

    class Boom(Exception):
        def __str__(self) -> str:
            return f"provider echoed {CANARY}"

    sanitized = sanitize_exception(Boom(), [CANARY, "sk_live_canary_sibling"])
    assert_canary_absent(sanitized, label="sanitized exception")
    assert "Boom" in sanitized


@pytest.mark.security
@pytest.mark.asyncio
@respx.mock
async def test_canary_http_error_bodies() -> None:
    from secretsync.infrastructure.http import HttpClientFactory, request_with_retries

    canary_body = f'{{"message":"denied {CANARY}"}}'
    route = respx.get("https://example.test/secret").mock(
        return_value=httpx.Response(403, text=canary_body, headers={"Authorization": "Bearer x"})
    )
    factory = HttpClientFactory()
    async with factory.create() as client:
        response = await request_with_retries(client, "GET", "https://example.test/secret")
    assert route.called
    assert response.status_code == 403
    from secretsync.infrastructure.http import error_for_status

    # Status-only mapping stays value-free.
    err = error_for_status(403, correlation_id="c1")
    assert_canary_absent(err.message, label="http safe error")
    assert CANARY not in (err.hint or "")

    # Provider body may be included when redacting known secrets.
    err_with_body = error_for_status(response, correlation_id="c1", secrets=[CANARY])
    assert_canary_absent(err_with_body.message, label="http safe error with body")
    assert "Provider rejected authorization (HTTP 403)" in err_with_body.message
    assert "denied" in err_with_body.message
    assert "***" in err_with_body.message
