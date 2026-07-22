"""Human-readable presentation."""

from __future__ import annotations

from secretsync.application.validate import ValidationResult
from secretsync.domain.models import Plan


def render_validation_human(result: ValidationResult) -> str:
    if result.ok:
        return "Configuration is valid."
    lines = ["Configuration is invalid:"]
    for issue in result.issues:
        lines.append(f"  [{issue.code}] {issue.message}")
        if issue.hint:
            lines.append(f"    hint: {issue.hint}")
    return "\n".join(lines)


def render_plan_human(plan: Plan) -> str:
    lines = [
        "SecretSync plan (always-write)",
        "Every listed target will be written. Values are never displayed.",
        f"Strategy: {plan.strategy}",
        f"Mutations: {len(plan.puts)}",
        "",
    ]
    current_deployment: str | None = None
    for put in plan.puts:
        if put.deployment_id != current_deployment:
            current_deployment = put.deployment_id
            lines.append(f"Deployment: {put.deployment_id}")
        scope = dict(put.target.scope)
        lines.append(
            f"  - {put.mutation_id}: {put.source.logical_id} "
            f"-> {put.target.destination_id}/{put.target.name} "
            f"[{put.target.connector_id}] scope={scope}"
        )
    return "\n".join(lines)
