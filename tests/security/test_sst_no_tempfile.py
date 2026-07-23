from __future__ import annotations

import sys
from pathlib import Path

import pytest

from secretsync.infrastructure.process import (
    ENV_FILE_PLACEHOLDER,
    AsyncSecureProcessRunner,
    EnvFileInput,
    SecureProcessRequest,
    build_minimal_child_env,
)

FD_READER = Path(__file__).resolve().parents[1] / "fixtures" / "fd_reader.py"
CANARY = b"SECRET_CANARY_nofile_a9f731"


@pytest.mark.asyncio
async def test_canary_never_written_to_disk(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    argv = (str(FD_READER), ENV_FILE_PLACEHOLDER)
    # Ensure canary is not in argv
    assert CANARY not in " ".join(argv).encode()

    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=argv,
            cwd=tmp_path,
            environment=build_minimal_child_env({"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}),
            env_file=EnvFileInput(variables={"SECRET": CANARY}),
            timeout_seconds=10.0,
        )
    )
    assert result.exit_code == 0

    artifacts = [p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()]
    assert all(CANARY not in blob for blob in artifacts)
    assert CANARY not in result.stderr_summary.encode()
