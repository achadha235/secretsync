from __future__ import annotations

import contextlib
from pathlib import Path

import pytest

from secretsync.application.services import create_services
from secretsync.presentation.json import apply_to_dict, render_apply_json
from secretsync.tui.app import SecretSyncApp
from secretsync.tui.screens import ConfigScreen, ConfirmScreen, PlanScreen, ResultsScreen
from tests.conftest import fixture_path

FAKE_ENV = {
    "YB_DATABASE_URL": "SECRET_CANARY_a9f731",
    "STRIPE_SECRET_KEY": "sk_live_canary",
    "API_TOKEN": "token_canary",
}
CANARY = "SECRET_CANARY_a9f731"


def _screen_text(app: SecretSyncApp) -> str:
    screen = app.screen
    parts: list[str] = []
    for node in screen.query("*"):
        parts.append(repr(node))
        update = getattr(node, "render", None)
        if callable(update):
            with contextlib.suppress(Exception):
                parts.append(str(update()))
        if hasattr(node, "renderable"):
            parts.append(str(node.renderable))
    return "\n".join(parts)


@pytest.mark.asyncio
async def test_pilot_config_plan_confirm_navigation() -> None:
    services = create_services(FAKE_ENV)
    app = SecretSyncApp(services=services, config_path=fixture_path("fake_apply.yaml"))
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)
        # Wait for validation worker
        for _ in range(40):
            status = str(app.screen.query_one("#status").render())
            if "OK" in status or "FAIL" in status:
                break
            await pilot.pause(0.05)
        status = str(app.screen.query_one("#status").render())
        assert "OK" in status
        assert CANARY not in status
        assert CANARY not in _screen_text(app)

        await pilot.click("#continue")
        await pilot.pause()
        assert isinstance(app.screen, PlanScreen)
        for _ in range(40):
            summary = str(app.screen.query_one("#plan-summary").render())
            if "OK" in summary or "FAIL" in summary:
                break
            await pilot.pause(0.05)
        summary = str(app.screen.query_one("#plan-summary").render())
        assert "OK" in summary
        assert "put" in summary.lower()
        assert CANARY not in summary
        assert CANARY not in _screen_text(app)

        await pilot.click("#continue")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        warning = str(app.screen.query_one("#always-write-warning").render())
        assert "always-write" in warning.lower()
        assert CANARY not in _screen_text(app)

        await pilot.click("#cancel")
        await pilot.pause()
        assert isinstance(app.screen, PlanScreen)


@pytest.mark.asyncio
async def test_pilot_apply_results_export_value_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    services = create_services(FAKE_ENV)
    app = SecretSyncApp(services=services, config_path=fixture_path("fake_apply.yaml"))
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        for _ in range(40):
            if "OK" in str(app.screen.query_one("#status").render()):
                break
            await pilot.pause(0.05)
        await pilot.click("#continue")
        await pilot.pause()
        for _ in range(40):
            if "OK" in str(app.screen.query_one("#plan-summary").render()):
                break
            await pilot.pause(0.05)
        await pilot.click("#continue")
        await pilot.pause()
        await pilot.click("#apply")
        for _ in range(80):
            await pilot.pause(0.05)
            if isinstance(app.screen, ResultsScreen):
                break
        assert isinstance(app.screen, ResultsScreen)
        assert app.report is not None
        assert app.report.summary.applied == 4
        assert CANARY not in _screen_text(app)
        payload = apply_to_dict(app.report)
        blob = render_apply_json(app.report)
        assert CANARY not in blob
        assert "sk_live_canary" not in blob
        assert payload["summary"]["applied"] == 4

        await pilot.click("#export")
        await pilot.pause()
        export_path = tmp_path / "secretsync-apply-report.json"
        assert export_path.is_file()
        exported = export_path.read_text()
        assert CANARY not in exported
        assert "schemaVersion" in exported

        await pilot.click("#quit")
        await pilot.pause()
    assert app.return_value is not None
    assert app.return_value.exit_code == 0


@pytest.mark.asyncio
async def test_pilot_snapshot_has_no_secret_values() -> None:
    services = create_services(FAKE_ENV)
    app = SecretSyncApp(services=services, config_path=fixture_path("fake_apply.yaml"))
    async with app.run_test(size=(100, 40)) as pilot:
        await pilot.pause()
        await pilot.click("#continue")
        await pilot.pause()
        for _ in range(40):
            if isinstance(app.screen, PlanScreen) and "OK" in str(
                app.screen.query_one("#plan-summary").render()
            ):
                break
            await pilot.pause(0.05)
        combined = _screen_text(app)
        assert CANARY not in combined
        assert "sk_live_canary" not in combined
        assert "token_canary" not in combined
        assert isinstance(app.screen, PlanScreen)
