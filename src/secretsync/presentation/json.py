"""Versioned JSON presentation (value-free)."""

from __future__ import annotations

import json
from typing import Any

from secretsync.application.apply import ApplyReport
from secretsync.application.validate import ValidationResult
from secretsync.domain.models import Plan


def validation_to_dict(result: ValidationResult) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "ok": result.ok,
        "exitCode": result.exit_code,
        "issues": [
            {
                "code": issue.code,
                "message": issue.message,
                "hint": issue.hint,
            }
            for issue in result.issues
        ],
    }


def plan_to_dict(plan: Plan) -> dict[str, Any]:
    destinations: dict[str, dict[str, Any]] = {}
    for put in plan.puts:
        dest = destinations.setdefault(
            put.target.destination_id,
            {
                "id": put.target.destination_id,
                "connector": put.target.connector_id,
                "puts": [],
                "deletes": [],
            },
        )
        dest["puts"].append(
            {
                "mutationId": put.mutation_id,
                "deployment": put.deployment_id,
                "logicalId": put.source.logical_id,
                "sourceEnv": put.source.env_name,
                "name": put.target.name,
                "scopes": [dict(put.target.scope)],
                "operation": "put",
            }
        )
    for deletion in plan.deletes:
        dest = destinations.setdefault(
            deletion.target.destination_id,
            {
                "id": deletion.target.destination_id,
                "connector": deletion.target.connector_id,
                "puts": [],
                "deletes": [],
            },
        )
        dest.setdefault("deletes", [])
        dest["deletes"].append(
            {
                "mutationId": deletion.mutation_id,
                "deployment": deletion.deployment_id,
                "name": deletion.target.name,
                "scopes": [dict(deletion.target.scope)],
                "operation": "delete",
            }
        )
    return {
        "schemaVersion": 1,
        "strategy": plan.strategy,
        "summary": {"puts": len(plan.puts), "deletes": len(plan.deletes)},
        "destinations": list(destinations.values()),
    }


def apply_to_dict(report: ApplyReport) -> dict[str, Any]:
    destinations: list[dict[str, Any]] = []
    for block in report.destinations:
        destinations.append(
            {
                "id": block.id,
                "connector": block.connector,
                "requestsMade": block.requests_made,
                "results": [
                    {
                        "mutationId": result.mutation_id,
                        "status": result.status,
                        "effect": result.effect,
                        "error": (
                            None
                            if result.error is None
                            else {
                                "code": result.error.code,
                                "message": result.error.message,
                                "hint": result.error.hint,
                                "retryable": result.error.retryable,
                                "correlationId": result.error.correlation_id,
                            }
                        ),
                    }
                    for result in block.results
                ],
            }
        )
    payload: dict[str, Any] = {
        "schemaVersion": 1,
        "strategy": report.strategy,
        "startedAt": report.started_at.isoformat() if report.started_at else None,
        "completedAt": report.completed_at.isoformat() if report.completed_at else None,
        "summary": {
            "applied": report.summary.applied,
            "failed": report.summary.failed,
            "skipped": report.summary.skipped,
        },
        "destinations": destinations,
        "exitCode": report.exit_code,
        "cancelled": report.cancelled,
    }
    if report.error is not None:
        payload["error"] = {
            "code": report.error.code,
            "message": report.error.message,
            "hint": report.error.hint,
        }
    return payload


def render_validation_json(result: ValidationResult) -> str:
    return json.dumps(validation_to_dict(result), indent=2, sort_keys=True)


def render_plan_json(plan: Plan) -> str:
    return json.dumps(plan_to_dict(plan), indent=2, sort_keys=True)


def render_apply_json(report: ApplyReport) -> str:
    return json.dumps(apply_to_dict(report), indent=2, sort_keys=True)
