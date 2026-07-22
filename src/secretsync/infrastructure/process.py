"""Secure process runner with inherited anonymous env-file descriptor."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import anyio

from secretsync.domain.errors import SafeError
from secretsync.infrastructure.dotenv import DotenvEncodeError, stream_dotenv
from secretsync.infrastructure.redaction import sanitize_provider_message

# Alias kept local so infrastructure does not import destinations (circular).
SafeConnectorError = SafeError

ENV_FILE_FD = 3
BOUNDED_STDERR = 4096

_BASE_ENV_KEYS = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "TERM",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
    }
)


@dataclass(frozen=True, slots=True)
class EnvFileInput:
    variables: Mapping[str, bytes | bytearray]
    file_descriptor: int = ENV_FILE_FD


@dataclass(frozen=True, slots=True)
class SecureProcessRequest:
    executable: Path
    arguments: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    env_file: EnvFileInput | None = None
    stdin_bytes: bytes | bytearray | None = None
    timeout_seconds: float = 30.0


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    duration_ms: int
    stderr_summary: str = ""


class ProcessRunnerError(Exception):
    def __init__(self, safe: SafeConnectorError) -> None:
        self.safe = safe
        super().__init__(safe.message)


def preferred_fd_path(fd: int = ENV_FILE_FD) -> str:
    """Platform preferred path for an inherited descriptor."""
    proc = f"/proc/self/fd/{fd}"
    if sys.platform.startswith("linux") and os.path.exists(proc):
        return proc
    return f"/dev/fd/{fd}"


def build_minimal_child_env(parent: Mapping[str, str]) -> dict[str, str]:
    """Allow-list PATH/HOME/etc. plus AWS_* — never copy full secret-laden environ."""
    child: dict[str, str] = {}
    for key, value in parent.items():
        if key in _BASE_ENV_KEYS or key.startswith("LC_") or key.startswith("AWS_"):
            child[key] = value
    child.setdefault("PATH", parent.get("PATH", "/usr/bin:/bin"))
    return child


def resolve_executable(name: str) -> Path | None:
    found = shutil.which(name)
    return Path(found) if found else None


def _stderr_summary(data: bytes | None) -> str:
    return sanitize_provider_message(
        (data or b"")[:BOUNDED_STDERR].decode("utf-8", errors="replace")
    )


@dataclass(frozen=True, slots=True)
class AsyncSecureProcessRunner:
    """Spawn children with optional inherited env-file descriptor (fd 3)."""

    async def execute(self, request: SecureProcessRequest) -> ProcessResult:
        started = time.monotonic()
        if request.env_file is not None and request.stdin_bytes is not None:
            raise ProcessRunnerError(
                SafeConnectorError(
                    code="PROCESS_FAILED",
                    message="env_file and stdin_bytes cannot both be set",
                )
            )
        try:
            if request.env_file is not None:
                result = await anyio.to_thread.run_sync(self._execute_with_env_file_sync, request)
            else:
                result = await anyio.to_thread.run_sync(self._execute_plain_sync, request)
        except ProcessRunnerError:
            raise
        except TimeoutError as exc:
            raise ProcessRunnerError(
                SafeConnectorError(
                    code="PROCESS_FAILED",
                    message="Provider CLI timed out",
                    retryable=False,
                )
            ) from exc
        except OSError as exc:
            errno = getattr(exc, "errno", None)
            if errno in {getattr(os, "EPIPE", 32)}:
                raise ProcessRunnerError(
                    SafeConnectorError(
                        code="PROCESS_FAILED",
                        message="Provider CLI closed the env-file pipe early (EPIPE)",
                    )
                ) from exc
            raise ProcessRunnerError(
                SafeConnectorError(
                    code="PROCESS_DESCRIPTOR_UNSUPPORTED",
                    message=f"Process spawn failed: {type(exc).__name__}",
                )
            ) from exc

        duration_ms = int((time.monotonic() * 1000) - (started * 1000))
        return ProcessResult(
            exit_code=result.exit_code,
            duration_ms=duration_ms,
            stderr_summary=result.stderr_summary,
        )

    def _execute_plain_sync(self, request: SecureProcessRequest) -> ProcessResult:
        stdin_payload = bytes(request.stdin_bytes) if request.stdin_bytes is not None else None
        proc = subprocess.Popen(  # noqa: S603
            [str(request.executable), *request.arguments],
            cwd=str(request.cwd),
            env=dict(request.environment),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_payload is not None else subprocess.DEVNULL,
            close_fds=True,
        )
        try:
            _, stderr_b = proc.communicate(input=stdin_payload, timeout=request.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.wait()
            raise TimeoutError("process timed out") from exc
        return ProcessResult(
            exit_code=int(proc.returncode or 0),
            duration_ms=0,
            stderr_summary=_stderr_summary(stderr_b),
        )

    def _execute_with_env_file_sync(self, request: SecureProcessRequest) -> ProcessResult:
        assert request.env_file is not None
        if request.env_file.file_descriptor != ENV_FILE_FD:
            raise ProcessRunnerError(
                SafeConnectorError(
                    code="PROCESS_DESCRIPTOR_UNSUPPORTED",
                    message=(f"Only descriptor {ENV_FILE_FD} is supported for env-file pipes"),
                )
            )

        # Map the pipe read end onto fd 3 in the *parent* before spawn.
        # preexec_fn + close_fds cannot keep fd 3: close_fds runs after
        # preexec and closes descriptors not listed in pass_fds.
        read_fd, write_fd = os.pipe()
        saved_fd3 = -1
        proc: subprocess.Popen[bytes] | None = None
        try:
            with contextlib.suppress(OSError):
                saved_fd3 = os.dup(ENV_FILE_FD)
            os.dup2(read_fd, ENV_FILE_FD)
            if read_fd != ENV_FILE_FD:
                os.close(read_fd)
            read_fd = -1

            proc = subprocess.Popen(  # noqa: S603
                [str(request.executable), *request.arguments],
                cwd=str(request.cwd),
                env=dict(request.environment),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                pass_fds=(ENV_FILE_FD,),
                close_fds=True,
            )

            # Child has its own copy of fd 3; restore the parent's table.
            if saved_fd3 >= 0:
                os.dup2(saved_fd3, ENV_FILE_FD)
                os.close(saved_fd3)
                saved_fd3 = -1
            else:
                with contextlib.suppress(OSError):
                    os.close(ENV_FILE_FD)

            try:

                def _write(chunk: bytes) -> None:
                    os.write(write_fd, chunk)

                stream_dotenv(request.env_file.variables, _write)
            except BrokenPipeError as exc:
                raise OSError(getattr(os, "EPIPE", 32), "EPIPE") from exc
            except DotenvEncodeError as exc:
                raise ProcessRunnerError(
                    SafeConnectorError(code="DESTINATION_INVALID", message=str(exc))
                ) from exc
            finally:
                with contextlib.suppress(OSError):
                    os.close(write_fd)
                write_fd = -1

            try:
                _, stderr_b = proc.communicate(timeout=request.timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                proc.kill()
                proc.wait()
                raise TimeoutError("process timed out") from exc
            return ProcessResult(
                exit_code=int(proc.returncode or 0),
                duration_ms=0,
                stderr_summary=_stderr_summary(stderr_b),
            )
        finally:
            if saved_fd3 >= 0:
                with contextlib.suppress(OSError):
                    os.dup2(saved_fd3, ENV_FILE_FD)
                    os.close(saved_fd3)
            if read_fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(read_fd)
            if write_fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(write_fd)
            if proc is not None and proc.poll() is None:
                proc.kill()
                proc.wait()


async def probe_env_file_descriptor(
    runner: AsyncSecureProcessRunner,
    *,
    reader_executable: Path,
    reader_args: tuple[str, ...] = (),
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Non-secret probe: stream a known token through fd 3 to a local reader."""
    env = dict(environment or build_minimal_child_env(os.environ))
    fd_path = preferred_fd_path(ENV_FILE_FD)
    request = SecureProcessRequest(
        executable=reader_executable,
        arguments=(*reader_args, fd_path),
        cwd=cwd or Path.cwd(),
        environment=env,
        env_file=EnvFileInput(variables={"PROBE": b"probe-token"}),
        timeout_seconds=10.0,
    )
    try:
        result = await runner.execute(request)
    except ProcessRunnerError:
        return False
    return result.exit_code == 0
