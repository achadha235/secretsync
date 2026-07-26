from __future__ import annotations

import shutil

from secretsync.application.apply import run_apply
from secretsync.application.services import create_services
from secretsync.infrastructure.audit import AUDIT_FILE, actor_context, record_audit
from tests.conftest import fixture_path

FAKE_ENV = {
    "YB_DATABASE_URL": "SECRET_CANARY_a9f731",
    "STRIPE_SECRET_KEY": "sk_live_canary",
    "API_TOKEN": "token_canary",
}


def test_record_audit_includes_actor_and_run(tmp_path) -> None:
    path = record_audit(
        command="health",
        config_path=None,
        exit_code=0,
        cwd=tmp_path,
        run_id="abc123def456",
    )
    line = path.read_text(encoding="utf-8").strip()
    assert "event=command" in line
    assert "cmd=health" in line
    assert "run=abc123def456" in line
    assert "user=" in line
    assert "host=" in line
    assert "ip=" in line
    assert "mac=" in line
    assert "pid=" in line
    assert actor_context() in line


def test_apply_writes_mutation_audit_without_values(tmp_path) -> None:
    config = tmp_path / "secretsync.yaml"
    shutil.copy(fixture_path("fake_apply.yaml"), config)
    run_id = "testrun000001"
    report = run_apply(
        create_services(FAKE_ENV),
        config_path=config,
        confirm=False,
        max_concurrency=4,
        run_id=run_id,
    )
    assert report.exit_code == 0
    assert report.summary.applied == 4

    log = (tmp_path / ".secretsync" / AUDIT_FILE).read_text(encoding="utf-8")
    mutations = [ln for ln in log.splitlines() if "event=mutation" in ln]
    assert len(mutations) == 4
    for line in mutations:
        assert f"run={run_id}" in line
        assert "user=" in line
        assert "op=put" in line
        assert "name=" in line
        assert "status=applied" in line
        assert "dest=" in line
        assert "SECRET_CANARY_a9f731" not in line
        assert "sk_live_canary" not in line
        assert "token_canary" not in line

    assert "name=DATABASE_URL" in log
    assert "name=STRIPE_SECRET_KEY" in log
    assert "name=API_TOKEN" in log


def test_apply_writes_failed_mutation_error_message(tmp_path) -> None:
    from secretsync.infrastructure.audit import record_mutation_audit

    path = record_mutation_audit(
        config_path=None,
        run_id="runfail00001",
        destination_id="github-org",
        connector_id="github-actions",
        deployment_id="production",
        op="put",
        name="SECRET_THREE_ORG",
        scope={"kind": "organization", "visibility": "all"},
        status="failed",
        effect=None,
        correlation_id="corr-1",
        error_code="DESTINATION_INVALID",
        error_message="Provider rejected request (HTTP 404): Not Found",
        cwd=tmp_path,
    )
    line = path.read_text(encoding="utf-8").strip()
    assert 'error_message="Provider rejected request (HTTP 404): Not Found"' in line
    assert "error=DESTINATION_INVALID" in line
