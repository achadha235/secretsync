from __future__ import annotations

from secretsync.application.apply import run_apply
from secretsync.application.services import create_services
from secretsync.destinations.fake import FakeIndividualFactory
from secretsync.destinations.registry import ConnectorRegistry
from tests.conftest import fixture_path

FAKE_ENV = {
    "YB_DATABASE_URL": "SECRET_CANARY_a9f731",
    "STRIPE_SECRET_KEY": "sk_live_canary",
    "API_TOKEN": "token_canary",
}


def test_apply_success_with_fakes() -> None:
    services = create_services(FAKE_ENV)
    report = run_apply(
        services,
        config_path=fixture_path("fake_apply.yaml"),
        confirm=False,
        max_concurrency=4,
    )
    assert report.exit_code == 0
    assert report.summary.applied == 4
    assert report.summary.failed == 0
    # batchSink: 2 mutations -> 1 request; individualSink: 2 mutations -> 2 requests
    by_id = {b.id: b for b in report.destinations}
    assert by_id["batchSink"].requests_made == 1
    assert by_id["individualSink"].requests_made == 2


def test_apply_confirmation_declined() -> None:
    services = create_services(FAKE_ENV)
    report = run_apply(
        services,
        config_path=fixture_path("fake_apply.yaml"),
        confirm=True,
        max_concurrency=2,
        confirm_fn=lambda _prompt: False,
    )
    assert report.exit_code == 0
    assert report.summary.applied == 0
    assert report.destinations == ()


def test_apply_unknown_connector_rejected() -> None:
    services = create_services({"A_ENV": "x", "TOKEN_ENV": "t"})
    report = run_apply(
        services,
        config_path=fixture_path("unknown_connector.yaml"),
        confirm=False,
        max_concurrency=2,
    )
    assert report.exit_code == 2
    assert report.error is not None
    assert "unknown" in report.error.message.lower()


def test_apply_partial_failure_exit_code() -> None:
    # Use a custom registry with a failing individual destination factory.
    from secretsync.application.services import (
        AppServices,
        SystemClock,
    )
    from secretsync.config.loader import ConfigLoader
    from secretsync.infrastructure.http import HttpClientFactory
    from secretsync.infrastructure.process import AsyncSecureProcessRunner
    from secretsync.sources.environment import EnvironmentSource

    class FailingFactory(FakeIndividualFactory):
        def create(self, services: object) -> object:
            dest = super().create(services)
            dest.fail_names = {"FAIL_ME"}
            return dest

    environ = {"YB_DATABASE_URL": "secret-value"}
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
    assert report.exit_code == 6
    assert report.summary.failed == 1
    assert report.summary.applied == 0


def test_apply_report_contains_no_secret_values() -> None:
    services = create_services(FAKE_ENV)
    report = run_apply(
        services,
        config_path=fixture_path("fake_apply.yaml"),
        confirm=False,
        max_concurrency=4,
    )
    blob = repr(report)
    for value in FAKE_ENV.values():
        assert value not in blob
