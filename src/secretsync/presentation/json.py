"""Versioned JSON presentation (value-free)."""

from __future__ import annotations

import json
from typing import Any

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
    return {
        "schemaVersion": 1,
        "strategy": plan.strategy,
        "summary": {"puts": len(plan.puts)},
        "destinations": list(destinations.values()),
    }


def render_validation_json(result: ValidationResult) -> str:
    return json.dumps(validation_to_dict(result), indent=2, sort_keys=True)


def render_plan_json(plan: Plan) -> str:
    return json.dumps(plan_to_dict(plan), indent=2, sort_keys=True)
