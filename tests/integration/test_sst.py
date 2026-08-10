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
    ENV_FILE_PLACEHOLDER,
    AsyncSecureProcessRunner,
    ProcessResult,
    SecureProcessRequest,
)


@dataclass
class RecordingRunner:
    calls: list[SecureProcessRequest] = field(default_factory=list)
    exit_code: int = 0
    stdout_bytes: bytes = b""
    stderr_summary: str = ""

    async def execute(self, request: SecureProcessRequest) -> ProcessResult:
        self.calls.append(request)
        return ProcessResult(
            exit_code=self.exit_code,
            duration_ms=1,
            stderr_summary=self.stderr_summary,
            stdout_bytes=self.stdout_bytes if request.capture_stdout else b"",
        )


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
    assert ENV_FILE_PLACEHOLDER in call.arguments
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


@pytest.mark.asyncio
async def test_list_names_parses_dotenv_stdout(tmp_path: Path) -> None:
    runner = RecordingRunner(stdout_bytes=b'Keep="x"\nOrphan="y"\n')
    dest = _dest(tmp_path, runner)
    names = await dest.list_names(
        {
            "connector": "sst",
            "workingDirectory": str(tmp_path),
            "executable": "sst",
        },
        {"stage": "production", "fallback": False},
        OperationContext(correlation_id="c1"),
    )
    assert names == frozenset({"Keep", "Orphan"})
    assert "secret" in runner.calls[0].arguments and "list" in runner.calls[0].arguments
    assert runner.calls[0].capture_stdout is True


_SECTIONED_LIST = b"""# fallback
TEST_SECRET=meow

# yellowbrick/staging
STRIPE_API_KEY=meow
YB_DATABASE_URL=meow
"""


@pytest.mark.asyncio
async def test_list_names_excludes_fallback_section_for_stage_scope(tmp_path: Path) -> None:
    runner = RecordingRunner(stdout_bytes=_SECTIONED_LIST)
    dest = _dest(tmp_path, runner)
    names = await dest.list_names(
        {
            "connector": "sst",
            "workingDirectory": str(tmp_path),
            "executable": "sst",
        },
        {"stage": "staging", "fallback": False},
        OperationContext(correlation_id="c1"),
    )
    assert names == frozenset({"STRIPE_API_KEY", "YB_DATABASE_URL"})
    assert "TEST_SECRET" not in names
    assert "--fallback" not in runner.calls[0].arguments


@pytest.mark.asyncio
async def test_list_names_fallback_scope_returns_fallback_section_only(
    tmp_path: Path,
) -> None:
    runner = RecordingRunner(stdout_bytes=_SECTIONED_LIST)
    dest = _dest(tmp_path, runner)
    names = await dest.list_names(
        {
            "connector": "sst",
            "workingDirectory": str(tmp_path),
            "executable": "sst",
        },
        {"stage": "staging", "fallback": True},
        OperationContext(correlation_id="c1"),
    )
    assert names == frozenset({"TEST_SECRET"})
    assert "--fallback" in runner.calls[0].arguments


@pytest.mark.asyncio
async def test_list_names_empty_inventory_is_not_failure(tmp_path: Path) -> None:
    """SST exits non-zero with 'No secrets found' when inventory is empty."""
    from secretsync.destinations.base import ListNamesError

    runner = RecordingRunner(
        exit_code=1,
        stderr_summary="✕  No secrets found",
    )
    dest = _dest(tmp_path, runner)
    names = await dest.list_names(
        {
            "connector": "sst",
            "workingDirectory": str(tmp_path),
            "executable": "sst",
        },
        {"stage": "staging", "fallback": True},
        OperationContext(correlation_id="c1"),
    )
    assert names == frozenset()

    runner_fail = RecordingRunner(exit_code=1, stderr_summary="network timeout")
    dest_fail = _dest(tmp_path, runner_fail)
    with pytest.raises(ListNamesError) as excinfo:
        await dest_fail.list_names(
            {
                "connector": "sst",
                "workingDirectory": str(tmp_path),
                "executable": "sst",
            },
            {"stage": "staging", "fallback": False},
            OperationContext(correlation_id="c1"),
        )
    assert "SST secret list failed" in excinfo.value.safe.message


@pytest.mark.asyncio
async def test_delete_calls_secret_remove(tmp_path: Path) -> None:
    from secretsync.destinations.base import DeleteMutation

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
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:Orphan",
                    name="Orphan",
                    scopes=({"stage": "production", "fallback": False},),
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"
    assert "remove" in runner.calls[0].arguments
    assert "Orphan" in runner.calls[0].arguments
    assert "--fallback" not in runner.calls[0].arguments


@pytest.mark.asyncio
async def test_delete_fallback_passes_fallback_flag(tmp_path: Path) -> None:
    from secretsync.destinations.base import DeleteMutation

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
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:TEST_SECRET",
                    name="TEST_SECRET",
                    scopes=({"stage": "staging", "fallback": True},),
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"
    assert "remove" in runner.calls[0].arguments
    assert "TEST_SECRET" in runner.calls[0].arguments
    assert "--fallback" in runner.calls[0].arguments
