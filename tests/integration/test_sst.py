from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from secretsync.destinations.base import (
    ApplyDestinationRequest,
    OperationContext,
    PutMutation,
)
from secretsync.destinations.sst import SstDestination, SstFactory
from secretsync.infrastructure.process import (
    AsyncSecureProcessRunner,
    ProcessResult,
    SecureProcessRequest,
)


@dataclass
class RecordingRunner:
    calls: list[SecureProcessRequest] = field(default_factory=list)
    exit_code: int = 0

    async def execute(self, request: SecureProcessRequest) -> ProcessResult:
        self.calls.append(request)
        return ProcessResult(exit_code=self.exit_code, duration_ms=1, stderr_summary="")


def _dest(tmp_path: Path, runner: Any, *, probe_ok: bool = True) -> SstDestination:
    dest = SstDestination(
        manifest=SstFactory().manifest,
        environ={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)},
        process_runner=runner,
    )
    # Bypass executable resolution / probe for unit integration of apply paths.
    dest._resolved_executable = Path("/usr/bin/sst")
    dest._argv_prefix = ()
    dest._probe_ok = probe_ok
    return dest


def _mutation(name: str, *, stage: str = "production", fallback: bool = False) -> PutMutation:
    return PutMutation(
        mutation_id=f"dep:{name}",
        name=name,
        value=bytearray(b"SECRET_CANARY_sst"),
        scopes=({"stage": stage, "fallback": fallback},),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_bulk_load_when_multiple_and_probe_ok(tmp_path: Path) -> None:
    runner = RecordingRunner()
    dest = _dest(tmp_path, runner, probe_ok=True)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "sst",
                "workingDirectory": str(tmp_path),
                "executable": "sst",
            },
            mutations=[_mutation("DatabaseUrl"), _mutation("StripeSecretKey")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "applied" for r in result.results)
    assert len(runner.calls) == 1
    call = runner.calls[0]
    assert call.env_file is not None
    assert "secret" in call.arguments and "load" in call.arguments
    assert "--stage" in call.arguments
    assert "production" in call.arguments
    assert "SECRET_CANARY_sst" not in repr(result)


@pytest.mark.asyncio
async def test_individual_set_when_single_or_probe_false(tmp_path: Path) -> None:
    runner = RecordingRunner()
    dest = _dest(tmp_path, runner, probe_ok=False)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "sst",
                "workingDirectory": str(tmp_path),
                "executable": "sst",
            },
            mutations=[_mutation("DatabaseUrl"), _mutation("StripeSecretKey")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 2
    assert all(r.status == "applied" for r in result.results)
    assert all(c.stdin_bytes is not None and c.env_file is None for c in runner.calls)
    assert all("set" in c.arguments for c in runner.calls)
    # Value never on argv
    for call in runner.calls:
        assert b"SECRET_CANARY_sst" not in " ".join(call.arguments).encode()


@pytest.mark.asyncio
async def test_fallback_flag(tmp_path: Path) -> None:
    runner = RecordingRunner()
    dest = _dest(tmp_path, runner, probe_ok=True)
    await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "sst",
                "workingDirectory": str(tmp_path),
                "executable": "sst",
            },
            mutations=[
                _mutation("A", fallback=True),
                _mutation("B", fallback=True),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert "--fallback" in runner.calls[0].arguments


@pytest.mark.asyncio
async def test_bulk_failure_fanout(tmp_path: Path) -> None:
    runner = RecordingRunner(exit_code=1)
    dest = _dest(tmp_path, runner, probe_ok=True)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "sst",
                "workingDirectory": str(tmp_path),
                "executable": "sst",
            },
            mutations=[_mutation("A"), _mutation("B")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "failed" for r in result.results)
    assert result.results[0].error is not None
    assert result.results[0].error.correlation_id == "c1"


@pytest.mark.asyncio
async def test_validate_requires_working_directory() -> None:
    dest = SstFactory().create(
        type("S", (), {"environ": {}, "process_runner": AsyncSecureProcessRunner()})()
    )
    issues = await dest.validate({"connector": "sst", "executable": "sst"})
    assert any("workingDirectory" in i.message for i in issues)
