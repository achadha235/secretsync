from __future__ import annotations

import sys
from pathlib import Path

import pytest

from secretsync.infrastructure.process import (
    AsyncSecureProcessRunner,
    EnvFileInput,
    SecureProcessRequest,
    build_minimal_child_env,
    preferred_fd_path,
    probe_env_file_descriptor,
)

FD_READER = Path(__file__).resolve().parents[1] / "fixtures" / "fd_reader.py"
CANARY = b"SECRET_CANARY_pipe_a9f731"


@pytest.mark.asyncio
async def test_env_file_pipe_delivers_bytes(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    request = SecureProcessRequest(
        executable=Path(sys.executable),
        arguments=(str(FD_READER), preferred_fd_path()),
        cwd=tmp_path,
        environment=build_minimal_child_env({"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}),
        env_file=EnvFileInput(variables={"CANARY": CANARY}),
        timeout_seconds=10.0,
    )
    result = await runner.execute(request)
    assert result.exit_code == 0
    # No secret files left in workspace
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert CANARY not in path.read_bytes()


@pytest.mark.asyncio
async def test_probe_env_file_descriptor(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    ok = await probe_env_file_descriptor(
        runner,
        reader_executable=Path(sys.executable),
        reader_args=(str(FD_READER),),
        cwd=tmp_path,
        environment=build_minimal_child_env({"PATH": "/usr/bin:/bin"}),
    )
    assert ok is True


@pytest.mark.asyncio
async def test_stdin_set_path(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    # cat reads stdin and writes to a length-only check via python
    script = "import sys; data=sys.stdin.buffer.read(); sys.exit(0 if data==b'hello' else 1)"
    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=("-c", script),
            cwd=tmp_path,
            environment=build_minimal_child_env({"PATH": "/usr/bin:/bin"}),
            stdin_bytes=b"hello",
        )
    )
    assert result.exit_code == 0


def test_minimal_env_excludes_secrets() -> None:
    parent = {
        "PATH": "/bin",
        "HOME": "/home/u",
        "AWS_ACCESS_KEY_ID": "AKIAxxx",
        "YB_DATABASE_URL": "secret",
        "STRIPE_SECRET_KEY": "sk",
    }
    child = build_minimal_child_env(parent)
    assert "AWS_ACCESS_KEY_ID" in child
    assert "YB_DATABASE_URL" not in child
    assert "STRIPE_SECRET_KEY" not in child
