"""Human-readable presentation."""

from __future__ import annotations

from secretsync.application.apply import ApplyReport
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
        f"Puts: {len(plan.puts)}  Deletes: {len(plan.deletes)}",
        "",
    ]
    if plan.deletes:
        lines.extend(
            [
                "WARNING: --prune treats YAML as the full desired inventory for each",
                "destination scope. Remote secrets not listed in YAML will be deleted.",
                "",
            ]
        )
    current_deployment: str | None = None
    for put in plan.puts:
        if put.deployment_id != current_deployment:
            current_deployment = put.deployment_id
            lines.append(f"Deployment: {put.deployment_id}")
        scope = dict(put.target.scope)
        lines.append(
            f"  - put {put.mutation_id} ({put.source.kind.value}): {put.source.logical_id} "
            f"-> {put.target.destination_id}/{put.target.name} "
            f"[{put.target.connector_id}] scope={scope}"
        )
    if plan.deletes:
        lines.append("")
        lines.append("Deletes:")
        for deletion in plan.deletes:
            scope = dict(deletion.target.scope)
            lines.append(
                f"  - delete {deletion.mutation_id} ({deletion.kind.value}): "
                f"{deletion.target.destination_id}/{deletion.target.name} "
                f"[{deletion.target.connector_id}] scope={scope}"
            )
    return "\n".join(lines)


def render_apply_human(report: ApplyReport) -> str:
    if report.error is not None and not report.destinations:
        lines = [f"[{report.error.code}] {report.error.message}"]
        if report.error.hint:
            lines.append(f"hint: {report.error.hint}")
        return "\n".join(lines)

    lines = [
        "SecretSync apply report",
        f"Strategy: {report.strategy}",
        (
            f"Summary: applied={report.summary.applied} "
            f"failed={report.summary.failed} skipped={report.summary.skipped}"
        ),
        f"Exit code: {report.exit_code}",
        "",
    ]
    for block in report.destinations:
        lines.append(f"Destination: {block.id} [{block.connector}] requests={block.requests_made}")
        for result in block.results:
            effect = result.effect or "-"
            line = f"  - {result.mutation_id}: {result.status} effect={effect}"
            if result.error is not None:
                line += f" [{result.error.code}] {result.error.message}"
            lines.append(line)
            if result.error is not None and result.error.hint:
                lines.append(f"    hint: {result.error.hint}")
    if report.cancelled:
        lines.append("Interrupted: completed writes were not rolled back.")
    return "\n".join(lines)
