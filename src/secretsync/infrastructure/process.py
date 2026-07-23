"""Secure process runner with named-pipe env-file delivery."""

from __future__ import annotations

import contextlib
import os
import shutil
import subprocess
import tempfile
import threading
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

ENV_FILE_PLACEHOLDER = "{env_file}"
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


@dataclass(frozen=True, slots=True)
class SecureProcessRequest:
    executable: Path
    arguments: tuple[str, ...]
    cwd: Path
    environment: Mapping[str, str]
    env_file: EnvFileInput | None = None
    stdin_bytes: bytes | bytearray | None = None
    timeout_seconds: float = 30.0
    capture_stdout: bool = False


@dataclass(frozen=True, slots=True)
class ProcessResult:
    exit_code: int
    duration_ms: int
    stderr_summary: str = ""
    stdout_bytes: bytes = b""


class ProcessRunnerError(Exception):
    def __init__(self, safe: SafeConnectorError) -> None:
        self.safe = safe
        super().__init__(safe.message)


def named_pipes_supported() -> bool:
    return hasattr(os, "mkfifo")


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


def _stderr_summary(data: bytes | None, secrets: list[str] | None = None) -> str:
    return sanitize_provider_message(
        (data or b"")[:BOUNDED_STDERR].decode("utf-8", errors="replace"),
        secrets,
    )


def _secrets_from_request(request: SecureProcessRequest) -> list[str]:
    """Collect plaintext secret strings that might be echoed by a child on stderr."""
    secrets: list[str] = []
    if request.env_file is not None:
        for value in request.env_file.variables.values():
            secrets.append(bytes(value).decode("utf-8", errors="replace"))
    if request.stdin_bytes is not None:
        secrets.append(bytes(request.stdin_bytes).decode("utf-8", errors="replace"))
    return secrets


def _substitute_env_file_path(arguments: tuple[str, ...], pipe_path: str) -> tuple[str, ...]:
    return tuple(
        word.replace(ENV_FILE_PLACEHOLDER, pipe_path) if ENV_FILE_PLACEHOLDER in word else word
        for word in arguments
    )


def _unblock_fifo(pipe_path: str) -> None:
    """Open the FIFO for reading so a blocked writer can proceed or get EPIPE."""
    try:
        rd = os.open(pipe_path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return
    with contextlib.suppress(OSError):
        os.close(rd)


def _write_dotenv_to_fifo(
    pipe_path: str,
    variables: Mapping[str, bytes | bytearray],
    errors: list[BaseException],
) -> None:
    """Write dotenv lines to the named pipe. Blocks until a reader opens."""
    try:
        with open(pipe_path, "wb") as pipe:

            def _write(chunk: bytes) -> None:
                pipe.write(chunk)

            stream_dotenv(variables, _write)
    except BrokenPipeError as exc:
        errors.append(exc)
    except DotenvEncodeError as exc:
        errors.append(exc)
    except OSError as exc:
        errors.append(exc)


@dataclass(frozen=True, slots=True)
class AsyncSecureProcessRunner:
    """Spawn children with optional named-pipe env-file delivery."""

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
            stdout_bytes=result.stdout_bytes,
        )

    def _execute_plain_sync(self, request: SecureProcessRequest) -> ProcessResult:
        stdin_payload = bytes(request.stdin_bytes) if request.stdin_bytes is not None else None
        proc = subprocess.Popen(  # noqa: S603
            [str(request.executable), *request.arguments],
            cwd=str(request.cwd),
            env=dict(request.environment),
            stdout=subprocess.PIPE if request.capture_stdout else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE if stdin_payload is not None else subprocess.DEVNULL,
            close_fds=True,
        )
        try:
            stdout_b, stderr_b = proc.communicate(
                input=stdin_payload, timeout=request.timeout_seconds
            )
        except subprocess.TimeoutExpired as exc:
            proc.kill()
            proc.wait()
            raise TimeoutError("process timed out") from exc
        return ProcessResult(
            exit_code=int(proc.returncode or 0),
            duration_ms=0,
            stderr_summary=_stderr_summary(stderr_b, _secrets_from_request(request)),
            stdout_bytes=stdout_b or b"",
        )

    def _execute_with_env_file_sync(self, request: SecureProcessRequest) -> ProcessResult:
        assert request.env_file is not None
        if not named_pipes_supported():
            raise ProcessRunnerError(
                SafeConnectorError(
                    code="PROCESS_DESCRIPTOR_UNSUPPORTED",
                    message="Named pipes (mkfifo) are not supported on this platform",
                )
            )

        # ponytail: TemporaryDirectory + mkfifo — payload never hits disk; inode only
        with tempfile.TemporaryDirectory(prefix="secretsync-env-") as temp_dir:
            os.chmod(temp_dir, 0o700)
            pipe_path = os.path.join(temp_dir, ".env")
            os.mkfifo(pipe_path, 0o600)

            argv = _substitute_env_file_path(request.arguments, pipe_path)
            writer_errors: list[BaseException] = []
            writer = threading.Thread(
                target=_write_dotenv_to_fifo,
                args=(pipe_path, request.env_file.variables, writer_errors),
                daemon=True,
            )
            writer.start()

            proc: subprocess.Popen[bytes] | None = None
            try:
                proc = subprocess.Popen(  # noqa: S603
                    [str(request.executable), *argv],
                    cwd=str(request.cwd),
                    env=dict(request.environment),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.DEVNULL,
                    close_fds=True,
                )
                try:
                    _, stderr_b = proc.communicate(timeout=request.timeout_seconds)
                except subprocess.TimeoutExpired as exc:
                    proc.kill()
                    proc.wait()
                    _unblock_fifo(pipe_path)
                    writer.join(timeout=2.0)
                    raise TimeoutError("process timed out") from exc

                writer.join(timeout=request.timeout_seconds)
                if writer.is_alive():
                    _unblock_fifo(pipe_path)
                    writer.join(timeout=2.0)

                if writer_errors:
                    err = writer_errors[0]
                    if isinstance(err, DotenvEncodeError):
                        raise ProcessRunnerError(
                            SafeConnectorError(code="DESTINATION_INVALID", message=str(err))
                        ) from err
                    if isinstance(err, BrokenPipeError) or (
                        isinstance(err, OSError)
                        and getattr(err, "errno", None) == getattr(os, "EPIPE", 32)
                    ):
                        raise OSError(getattr(os, "EPIPE", 32), "EPIPE") from err
                    if isinstance(err, OSError):
                        raise err
                    raise ProcessRunnerError(
                        SafeConnectorError(
                            code="PROCESS_FAILED",
                            message=f"Env-file pipe writer failed: {type(err).__name__}",
                        )
                    ) from err

                return ProcessResult(
                    exit_code=int(proc.returncode or 0),
                    duration_ms=0,
                    stderr_summary=_stderr_summary(stderr_b, _secrets_from_request(request)),
                )
            finally:
                if writer.is_alive():
                    _unblock_fifo(pipe_path)
                    writer.join(timeout=2.0)
                if proc is not None and proc.poll() is None:
                    proc.kill()
                    proc.wait()


async def probe_env_file_pipe(
    runner: AsyncSecureProcessRunner,
    *,
    reader_executable: Path,
    reader_args: tuple[str, ...] = (),
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    """Non-secret probe: stream a known token through a named pipe to a local reader."""
    if not named_pipes_supported():
        return False
    env = dict(environment or build_minimal_child_env(os.environ))
    request = SecureProcessRequest(
        executable=reader_executable,
        arguments=(*reader_args, ENV_FILE_PLACEHOLDER),
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
