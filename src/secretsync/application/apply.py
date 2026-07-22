"""Apply orchestration — destination framework arrives in M2."""

from __future__ import annotations

from dataclasses import dataclass

from secretsync.application.services import AppServices
from secretsync.domain.errors import EXIT_CONFIG, SafeError


@dataclass(frozen=True, slots=True)
class ApplyReport:
    exit_code: int
    error: SafeError | None = None


def run_apply(
    services: AppServices,
    *,
    confirm: bool,
    max_concurrency: int,
) -> ApplyReport:
    del services, confirm, max_concurrency
    return ApplyReport(
        exit_code=EXIT_CONFIG,
        error=SafeError(
            code="CONFIG_INVALID",
            message="Apply is not available until destination connectors are implemented (M2+)",
            hint="Use secretsync validate and secretsync plan in M0/M1.",
        ),
    )
