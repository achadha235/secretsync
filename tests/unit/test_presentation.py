from __future__ import annotations

from datetime import UTC, datetime

import pytest

from secretsync.application.apply import ApplyReport, ApplySummary, DestinationApplyBlock
from secretsync.application.validate import ValidationIssue, ValidationResult
from secretsync.destinations.base import MutationResult
from secretsync.domain.errors import SafeError
from secretsync.domain.models import Plan, PlannedPut, SecretRef, TargetRef
from secretsync.presentation.human import (
    render_apply_human,
    render_plan_human,
    render_validation_human,
)
from secretsync.presentation.json import (
    apply_to_dict,
    plan_to_dict,
    render_apply_json,
    render_plan_json,
    render_validation_json,
    validation_to_dict,
)

CANARY = "SECRET_CANARY_present_a9f731"


def _put(
    *,
    mutation_id: str = "m1",
    deployment_id: str = "prod",
    dest: str = "gh",
    connector: str = "github-actions",
    name: str = "TOKEN",
    env_name: str = "API_TOKEN",
) -> PlannedPut:
    return PlannedPut(
        mutation_id=mutation_id,
        deployment_id=deployment_id,
        source=SecretRef(logical_id="api", env_name=env_name),
        target=TargetRef(
            destination_id=dest,
            connector_id=connector,
            name=name,
            scope={"environment": "production"},
        ),
    )


def test_validation_ok_and_issues() -> None:
    ok = ValidationResult(exit_code=0)
    ok.config = object()  # type: ignore[assignment]
    assert ok.ok
    assert render_validation_human(ok) == "Configuration is valid."
    payload = validation_to_dict(ok)
    assert payload["ok"] is True
    assert payload["schemaVersion"] == 1
    assert "SECRET_CANARY" not in render_validation_json(ok)

    bad = ValidationResult(
        issues=[
            ValidationIssue(
                code="SOURCE_MISSING",
                message="Required environment variable 'X' is absent",
                hint="Export X",
            ),
            ValidationIssue(code="CONFIG_INVALID", message="bad", hint=None),
        ],
        exit_code=3,
    )
    human = render_validation_human(bad)
    assert "[SOURCE_MISSING]" in human
    assert "hint: Export X" in human
    assert "[CONFIG_INVALID]" in human
    assert CANARY not in human
    data = validation_to_dict(bad)
    assert data["ok"] is False
    assert data["exitCode"] == 3
    assert data["issues"][0]["hint"] == "Export X"
    assert data["issues"][1]["hint"] is None


def test_plan_human_and_json_group_by_deployment() -> None:
    plan = Plan(
        strategy="always-write",
        puts=(
            _put(mutation_id="m1", deployment_id="prod", name="A"),
            _put(mutation_id="m2", deployment_id="prod", name="B"),
            _put(mutation_id="m3", deployment_id="staging", name="C", dest="vc"),
        ),
    )
    human = render_plan_human(plan)
    assert "SecretSync plan (always-write)" in human
    assert "Deployment: prod" in human
    assert "Deployment: staging" in human
    assert "m1" in human and "m3" in human
    assert "put m1 (secret):" in human
    assert "put m3 (secret):" in human
    assert CANARY not in human
    assert CANARY not in render_plan_json(plan)

    data = plan_to_dict(plan)
    assert data["summary"]["puts"] == 3
    assert data["summary"]["deletes"] == 0
    assert data["strategy"] == "always-write"
    dest_ids = {d["id"] for d in data["destinations"]}
    assert dest_ids == {"gh", "vc"}
    gh = next(d for d in data["destinations"] if d["id"] == "gh")
    assert len(gh["puts"]) == 2
    assert gh["puts"][0]["operation"] == "put"
    assert "scopes" in gh["puts"][0]


def test_apply_human_top_level_error_only() -> None:
    report = ApplyReport(
        exit_code=2,
        error=SafeError(
            code="CONFIG_INVALID",
            message="broken config",
            hint="fix yaml",
        ),
        destinations=(),
    )
    text = render_apply_human(report)
    assert text.startswith("[CONFIG_INVALID] broken config")
    assert "hint: fix yaml" in text
    assert "Summary:" not in text


def test_apply_human_and_json_full_paths() -> None:
    started = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    completed = datetime(2026, 1, 2, 3, 4, 6, tzinfo=UTC)
    err = SafeError(
        code="DESTINATION_RATE_LIMITED",
        message="slow down",
        hint="retry later",
        retryable=True,
        correlation_id="corr-1",
    )
    report = ApplyReport(
        exit_code=5,
        strategy="always-write",
        started_at=started,
        completed_at=completed,
        summary=ApplySummary(applied=1, failed=1, skipped=1),
        destinations=(
            DestinationApplyBlock(
                id="gh",
                connector="github-actions",
                requests_made=2,
                results=(
                    MutationResult(mutation_id="m1", status="applied", effect="upserted"),
                    MutationResult(mutation_id="m2", status="failed", effect=None, error=err),
                    MutationResult(mutation_id="m3", status="skipped", effect=None),
                ),
            ),
        ),
        error=SafeError(code="DESTINATION_RATE_LIMITED", message="overall", hint=None),
        cancelled=True,
    )
    human = render_apply_human(report)
    assert "applied=1 failed=1 skipped=1" in human
    assert "Destination: gh [github-actions] requests=2" in human
    assert "m1: applied effect=upserted" in human
    assert "m2: failed effect=- [DESTINATION_RATE_LIMITED] slow down" in human
    assert "Interrupted: completed writes were not rolled back." in human
    assert CANARY not in human

    data = apply_to_dict(report)
    assert data["startedAt"] == started.isoformat()
    assert data["completedAt"] == completed.isoformat()
    assert data["cancelled"] is True
    assert data["exitCode"] == 5
    assert data["error"]["code"] == "DESTINATION_RATE_LIMITED"
    failed = data["destinations"][0]["results"][1]
    assert failed["error"]["retryable"] is True
    assert failed["error"]["correlationId"] == "corr-1"
    blob = render_apply_json(report)
    assert CANARY not in blob
    assert "slow down" in blob


def test_apply_json_null_timestamps_and_no_top_error() -> None:
    report = ApplyReport(
        exit_code=0,
        summary=ApplySummary(1, 0, 0),
        destinations=(
            DestinationApplyBlock(
                id="x",
                connector="fake-individual",
                requests_made=1,
                results=(MutationResult("m", "applied", "created"),),
            ),
        ),
    )
    data = apply_to_dict(report)
    assert data["startedAt"] is None
    assert data["completedAt"] is None
    assert "error" not in data
    assert data["destinations"][0]["results"][0]["error"] is None


def test_apply_human_error_with_destinations_still_renders_summary() -> None:
    """Top-level error only short-circuits when destinations is empty."""
    report = ApplyReport(
        exit_code=5,
        error=SafeError(code="DESTINATION_INVALID", message="boom", hint=None),
        summary=ApplySummary(0, 1, 0),
        destinations=(
            DestinationApplyBlock(
                id="d",
                connector="fake-individual",
                requests_made=1,
                results=(
                    MutationResult(
                        "m",
                        "failed",
                        None,
                        SafeError(code="DESTINATION_INVALID", message="boom"),
                    ),
                ),
            ),
        ),
    )
    text = render_apply_human(report)
    assert "SecretSync apply report" in text
    assert "[DESTINATION_INVALID] boom" in text


@pytest.mark.parametrize(
    "renderer",
    [render_plan_human, render_plan_json],
)
def test_plan_renderers_never_include_secret_values(renderer: object) -> None:
    plan = Plan(strategy="always-write", puts=(_put(),))
    out = renderer(plan)  # type: ignore[operator]
    assert CANARY not in out
    assert "postgres://" not in out
