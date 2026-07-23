"""Apply orchestration: validate, plan, resolve, destination apply, report."""

from __future__ import annotations

import asyncio
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import anyio

from secretsync.application.plan import build_plan
from secretsync.application.services import AppServices
from secretsync.application.validate import ValidationIssue, validate_config
from secretsync.config.models import RootConfig
from secretsync.destinations.base import (
    ApplyDestinationRequest,
    ApplyDestinationResult,
    MutationResult,
    OperationContext,
    PutMutation,
    SafeConnectorError,
)
from secretsync.domain.errors import (
    EXIT_ALL_FAILED,
    EXIT_CONNECTOR_VALIDATION,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_PARTIAL,
    ConnectorNotImplementedError,
    SafeError,
    SecretSyncError,
    UnknownConnectorError,
    exit_code_for,
)
from secretsync.domain.models import JsonValue, Plan, PlannedPut
from secretsync.infrastructure.redaction import scrub_bytearray


@dataclass(frozen=True, slots=True)
class DestinationApplyBlock:
    id: str
    connector: str
    requests_made: int
    results: tuple[MutationResult, ...]


@dataclass(frozen=True, slots=True)
class ApplySummary:
    applied: int
    failed: int
    skipped: int


@dataclass(frozen=True, slots=True)
class DestinationProgress:
    """Value-free destination progress event for TUI / reporters."""

    destination_id: str
    connector: str
    phase: Literal["started", "finished"]
    applied: int = 0
    failed: int = 0
    skipped: int = 0


@dataclass(slots=True)
class ApplyReport:
    exit_code: int
    strategy: str = "always-write"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    summary: ApplySummary = field(default_factory=lambda: ApplySummary(0, 0, 0))
    destinations: tuple[DestinationApplyBlock, ...] = ()
    error: SafeError | None = None
    cancelled: bool = False


ConfirmFn = Callable[[str], bool]
ProgressFn = Callable[[DestinationProgress], None]


def run_apply(
    services: AppServices,
    *,
    config_path: Path,
    confirm: bool,
    max_concurrency: int,
    confirm_fn: ConfirmFn | None = None,
    on_destination_progress: ProgressFn | None = None,
    mutation_ids: frozenset[str] | None = None,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> ApplyReport:
    """Synchronous entry used by Click; runs the async coordinator."""

    async def _runner() -> ApplyReport:
        return await run_apply_async(
            services,
            config_path,
            confirm=confirm,
            max_concurrency=max_concurrency,
            confirm_fn=confirm_fn,
            on_destination_progress=on_destination_progress,
            mutation_ids=mutation_ids,
            deployments=deployments,
            destinations=destinations,
        )

    return anyio.run(_runner)


async def run_apply_async(
    services: AppServices,
    config_path: Path,
    *,
    confirm: bool,
    max_concurrency: int,
    confirm_fn: ConfirmFn | None = None,
    on_destination_progress: ProgressFn | None = None,
    mutation_ids: frozenset[str] | None = None,
    deployments: set[str] | None = None,
    destinations: set[str] | None = None,
) -> ApplyReport:
    """Async apply entry used by the Textual TUI workers."""
    from loguru import logger

    started = services.clock.now()
    validation = validate_config(
        services,
        config_path,
        deployments=deployments,
        destinations=destinations,
    )
    if not validation.ok or validation.config is None:
        issue = validation.issues[0] if validation.issues else None
        return ApplyReport(
            exit_code=validation.exit_code,
            started_at=started,
            completed_at=services.clock.now(),
            error=(
                SafeError(
                    code=issue.code if issue else "CONFIG_INVALID",
                    message=issue.message if issue else "Validation failed",
                    hint=issue.hint if issue else None,
                )
            ),
        )

    config = validation.config
    selected_dest_ids = {
        d.destination for d in config.deployments if d.name in set(validation.selected_deployments)
    }
    try:
        connector_issues = await _static_validate_connectors(
            services, config, destination_ids=selected_dest_ids or None
        )
    except SecretSyncError as exc:
        return ApplyReport(
            exit_code=exit_code_for(exc),
            started_at=started,
            completed_at=services.clock.now(),
            error=exc.safe,
        )
    if connector_issues:
        first = connector_issues[0]
        return ApplyReport(
            exit_code=EXIT_CONNECTOR_VALIDATION,
            started_at=started,
            completed_at=services.clock.now(),
            error=SafeError(
                code=first.code,
                message=first.message,
                hint=first.hint,
            ),
        )

    plan = build_plan(
        config,
        validation.composed_sets,
        deployments=deployments,
        destinations=destinations,
    )
    logger.info("Apply plan has {} put(s)", len(plan.puts))
    if mutation_ids is not None:
        filtered = tuple(put for put in plan.puts if put.mutation_id in mutation_ids)
        plan = Plan(strategy=plan.strategy, puts=filtered)

    if confirm:
        from secretsync.presentation.human import render_plan_human

        prompt = render_plan_human(plan) + "\n\nApply all listed writes?"
        accepted = (confirm_fn or _default_confirm)(prompt)
        if not accepted:
            return ApplyReport(
                exit_code=EXIT_OK,
                strategy=plan.strategy,
                started_at=started,
                completed_at=services.clock.now(),
                summary=ApplySummary(0, 0, len(plan.puts)),
            )

    try:
        blocks = await _apply_plan(
            services,
            config,
            plan,
            max_concurrency,
            on_destination_progress=on_destination_progress,
        )
    except (anyio.get_cancelled_exc_class(), asyncio.CancelledError):
        return ApplyReport(
            exit_code=EXIT_INTERRUPTED,
            strategy=plan.strategy,
            started_at=started,
            completed_at=services.clock.now(),
            cancelled=True,
            error=SafeError(
                code="CONFIG_INVALID",
                message="Apply interrupted; completed writes were not rolled back",
            ),
        )
    except SecretSyncError as exc:
        return ApplyReport(
            exit_code=exit_code_for(exc),
            strategy=plan.strategy,
            started_at=started,
            completed_at=services.clock.now(),
            error=exc.safe,
        )

    # Deterministic display order by destination id, then preserve plan order within.
    plan_dest_order = _destination_order(plan)
    ordered = tuple(sorted(blocks, key=lambda b: (plan_dest_order.get(b.id, 10_000), b.id)))
    summary = _summarize(ordered)
    exit_code = _exit_for_summary(summary)
    return ApplyReport(
        exit_code=exit_code,
        strategy=plan.strategy,
        started_at=started,
        completed_at=services.clock.now(),
        summary=summary,
        destinations=ordered,
    )


def _default_confirm(prompt: str) -> bool:
    import click

    click.echo(prompt)
    return bool(click.confirm("Continue?", default=False))


async def _static_validate_connectors(
    services: AppServices,
    config: RootConfig,
    *,
    destination_ids: set[str] | None = None,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for dest_id, destination in config.destinations.items():
        if destination_ids is not None and dest_id not in destination_ids:
            continue
        if not services.connectors.is_registered(destination.connector):
            if services.connectors.is_known(destination.connector):
                raise ConnectorNotImplementedError(destination.connector)
            raise UnknownConnectorError(destination.connector)
        instance = services.connectors.create(destination.connector, services)
        config_map = _destination_config_map(destination)
        found = await instance.validate(config_map)
        for issue in found:
            issues.append(
                ValidationIssue(
                    code=issue.code,
                    message=f"{dest_id}: {issue.message}",
                    hint=issue.hint,
                )
            )
    return issues


def _destination_config_map(destination: Any) -> dict[str, JsonValue]:
    raw = destination.model_dump(by_alias=True)
    return {str(k): _as_json(v) for k, v in raw.items()}


def _as_json(value: Any) -> JsonValue:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, list):
        return [_as_json(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _as_json(v) for k, v in value.items()}
    return str(value)


def _destination_order(plan: Plan) -> dict[str, int]:
    order: dict[str, int] = {}
    for put in plan.puts:
        order.setdefault(put.target.destination_id, len(order))
    return order


async def _apply_plan(
    services: AppServices,
    config: RootConfig,
    plan: Plan,
    max_concurrency: int,
    *,
    on_destination_progress: ProgressFn | None = None,
) -> list[DestinationApplyBlock]:
    by_destination: dict[str, list[PlannedPut]] = defaultdict(list)
    for put in plan.puts:
        by_destination[put.target.destination_id].append(put)

    limiter = anyio.CapacityLimiter(max_concurrency)
    results: dict[str, DestinationApplyBlock] = {}

    async def run_one(destination_id: str, puts: list[PlannedPut]) -> None:
        connector_id = config.destinations[destination_id].connector
        async with limiter:
            if on_destination_progress is not None:
                on_destination_progress(
                    DestinationProgress(
                        destination_id=destination_id,
                        connector=connector_id,
                        phase="started",
                    )
                )
            block = await _apply_destination(services, config, destination_id, puts)
            results[destination_id] = block
            if on_destination_progress is not None:
                part = _summarize([block])
                on_destination_progress(
                    DestinationProgress(
                        destination_id=destination_id,
                        connector=connector_id,
                        phase="finished",
                        applied=part.applied,
                        failed=part.failed,
                        skipped=part.skipped,
                    )
                )

    async with anyio.create_task_group() as tg:
        for destination_id, puts in by_destination.items():
            tg.start_soon(run_one, destination_id, puts)

    return list(results.values())


async def _apply_destination(
    services: AppServices,
    config: RootConfig,
    destination_id: str,
    puts: list[PlannedPut],
) -> DestinationApplyBlock:
    destination_def = config.destinations[destination_id]
    connector_id = destination_def.connector
    destination = services.connectors.create(connector_id, services)
    dest_config = _destination_config_map(destination_def)

    # Preserve plan order of deployments within this destination.
    by_deployment: dict[str, list[PlannedPut]] = defaultdict(list)
    deployment_order: list[str] = []
    for put in puts:
        if put.deployment_id not in by_deployment:
            deployment_order.append(put.deployment_id)
        by_deployment[put.deployment_id].append(put)

    all_results: list[MutationResult] = []
    requests_made = 0

    for deployment_id in deployment_order:
        deployment_puts = by_deployment[deployment_id]
        mutations: list[PutMutation] = []
        try:
            for put in deployment_puts:
                material = await services.source.resolve(put.source)
                mutations.append(
                    PutMutation(
                        mutation_id=put.mutation_id,
                        name=put.target.name,
                        value=material.value,
                        scopes=(dict(put.target.scope),),
                    )
                )
            context = OperationContext(correlation_id=str(uuid.uuid4()))
            request = ApplyDestinationRequest(
                deployment_id=deployment_id,
                destination_config=dest_config,
                mutations=mutations,
            )
            try:
                outcome = await destination.apply(request, context)
            except Exception as exc:  # noqa: BLE001 — convert to safe per-mutation failures
                secret_texts = [bytes(m.value).decode("utf-8", errors="replace") for m in mutations]
                outcome = _failure_result_for_request(
                    request,
                    message=sanitize_exception(exc, secret_texts),
                    correlation_id=context.correlation_id,
                )
            requests_made += outcome.requests_made
            all_results.extend(_correlate_results(request, outcome, context.correlation_id))
        finally:
            for mutation in mutations:
                scrub_bytearray(mutation.value)

    return DestinationApplyBlock(
        id=destination_id,
        connector=connector_id,
        requests_made=requests_made,
        results=tuple(all_results),
    )


def sanitize_exception(exc: BaseException, secrets: list[str] | None = None) -> str:
    from secretsync.infrastructure.redaction import sanitize_provider_message

    return sanitize_provider_message(
        f"{type(exc).__name__}: connector raised",
        secrets,
    )


def _failure_result_for_request(
    request: ApplyDestinationRequest,
    *,
    message: str,
    correlation_id: str,
) -> ApplyDestinationResult:
    error = SafeConnectorError(
        code="DESTINATION_INVALID",
        message=message,
        correlation_id=correlation_id,
    )
    return ApplyDestinationResult(
        results=tuple(
            MutationResult(
                mutation_id=m.mutation_id,
                status="failed",
                effect=None,
                error=error,
            )
            for m in request.mutations
        ),
        requests_made=1,
    )


def _correlate_results(
    request: ApplyDestinationRequest,
    outcome: ApplyDestinationResult,
    correlation_id: str,
) -> list[MutationResult]:
    by_id = {r.mutation_id: r for r in outcome.results}
    correlated: list[MutationResult] = []
    for mutation in request.mutations:
        existing = by_id.get(mutation.mutation_id)
        if existing is not None:
            correlated.append(existing)
            continue
        correlated.append(
            MutationResult(
                mutation_id=mutation.mutation_id,
                status="failed",
                effect=None,
                error=SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Connector omitted result for mutation",
                    mutation_id=mutation.mutation_id,
                    correlation_id=correlation_id,
                ),
            )
        )
    return correlated


def _summarize(
    blocks: tuple[DestinationApplyBlock, ...] | list[DestinationApplyBlock],
) -> ApplySummary:
    applied = failed = skipped = 0
    for block in blocks:
        for result in block.results:
            if result.status == "applied":
                applied += 1
            elif result.status == "failed":
                failed += 1
            else:
                skipped += 1
    return ApplySummary(applied=applied, failed=failed, skipped=skipped)


def _exit_for_summary(summary: ApplySummary) -> int:
    total = summary.applied + summary.failed + summary.skipped
    if total == 0:
        return EXIT_OK
    if summary.failed == 0 and summary.skipped == 0:
        return EXIT_OK
    if summary.applied == 0 and summary.failed > 0:
        return EXIT_ALL_FAILED
    if summary.failed > 0:
        return EXIT_PARTIAL
    return EXIT_OK
