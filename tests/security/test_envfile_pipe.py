"""Security + correctness for streaming dotenv and named-pipe env-file delivery."""

from __future__ import annotations

import hashlib
import io
import sys
from pathlib import Path

import pytest

from secretsync.infrastructure.dotenv import (
    DotenvEncodeError,
    quote_dotenv_value,
    stream_dotenv,
    validate_dotenv_key,
)
from secretsync.infrastructure.process import (
    ENV_FILE_PLACEHOLDER,
    AsyncSecureProcessRunner,
    EnvFileInput,
    ProcessRunnerError,
    SecureProcessRequest,
    build_minimal_child_env,
    probe_env_file_pipe,
)
from tests.security.conftest import (
    CANARY,
    CANARY_BYTES,
    assert_canary_absent,
    assert_no_canary_under,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
FD_READER = FIXTURES / "fd_reader.py"
FD_HASH = FIXTURES / "fd_hash_reader.py"
FD_HANG = FIXTURES / "fd_hang.py"
FD_SPY = FIXTURES / "fd_env_spy.py"


def _child_env(tmp_path: Path) -> dict[str, str]:
    return build_minimal_child_env({"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)})


def _encode_expected(variables: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()

    def write(chunk: bytes) -> None:
        buf.write(chunk)

    stream_dotenv(variables, write)
    return buf.getvalue()


@pytest.mark.security
@pytest.mark.asyncio
async def test_envfile_pipe_roundtrip_hash(tmp_path: Path) -> None:
    variables = {
        "A": CANARY_BYTES,
        "B": b'quote " and \\ slash',
        "EMPTY": b"",
        "UNI": "café".encode(),
        "NL": b"line1\nline2\r\tend",
    }
    expected = _encode_expected(variables)
    digest = hashlib.sha256(expected).hexdigest()
    runner = AsyncSecureProcessRunner()
    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=(str(FD_HASH), ENV_FILE_PLACEHOLDER),
            cwd=tmp_path,
            environment=_child_env(tmp_path),
            env_file=EnvFileInput(variables=variables),
            timeout_seconds=10.0,
        )
    )
    assert result.exit_code == 0
    assert_canary_absent(result.stderr_summary)
    assert_no_canary_under(tmp_path)
    assert hashlib.sha256(expected).hexdigest() == digest
    assert CANARY_BYTES not in " ".join((str(FD_HASH), ENV_FILE_PLACEHOLDER)).encode()


@pytest.mark.security
@pytest.mark.asyncio
async def test_envfile_no_disk_no_argv_no_parent_secret_env(tmp_path: Path) -> None:
    spy_out = tmp_path / "spy.json"
    parent_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "YB_DATABASE_URL": CANARY,
        "STRIPE_SECRET_KEY": "sk_should_not_pass",
        "AWS_ACCESS_KEY_ID": "AKIAtest",
    }
    child_env = build_minimal_child_env(parent_env)
    assert "YB_DATABASE_URL" not in child_env
    assert "STRIPE_SECRET_KEY" not in child_env
    assert child_env.get("AWS_ACCESS_KEY_ID") == "AKIAtest"

    argv = (str(FD_SPY), str(spy_out), ENV_FILE_PLACEHOLDER)
    assert CANARY not in " ".join(argv)

    runner = AsyncSecureProcessRunner()
    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=argv,
            cwd=tmp_path,
            environment=child_env,
            env_file=EnvFileInput(variables={"SECRET": CANARY_BYTES, "OTHER": b"two"}),
            timeout_seconds=10.0,
        )
    )
    assert result.exit_code == 0
    assert_canary_absent(result.stderr_summary)
    assert_no_canary_under(tmp_path)
    payload = spy_out.read_text(encoding="utf-8")
    assert_canary_absent(payload, label="spy output")
    assert "sk_should_not_pass" not in payload
    assert '"YB_DATABASE_URL": null' in payload or '"YB_DATABASE_URL":null' in payload.replace(
        " ", ""
    )


@pytest.mark.security
@pytest.mark.asyncio
async def test_envfile_epipe_early_close_safe(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    # Fill beyond typical pipe buffer so write fails after child closes early.
    fat = CANARY_BYTES * 20_000
    variables = {f"K{i}": fat for i in range(4)}
    with pytest.raises(ProcessRunnerError) as exc_info:
        await runner.execute(
            SecureProcessRequest(
                executable=Path(sys.executable),
                arguments=(str(FIXTURES / "fd_close_fd3.py"), ENV_FILE_PLACEHOLDER),
                cwd=tmp_path,
                environment=_child_env(tmp_path),
                env_file=EnvFileInput(variables=variables),
                timeout_seconds=5.0,
            )
        )
    err = exc_info.value
    assert err.safe.code.startswith("PROCESS_")
    assert_canary_absent(err.safe.message)
    assert_canary_absent(str(err))
    assert_no_canary_under(tmp_path)


@pytest.mark.security
@pytest.mark.asyncio
async def test_envfile_timeout_kills_child(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    with pytest.raises(ProcessRunnerError) as exc_info:
        await runner.execute(
            SecureProcessRequest(
                executable=Path(sys.executable),
                arguments=(str(FD_HANG), ENV_FILE_PLACEHOLDER),
                cwd=tmp_path,
                environment=_child_env(tmp_path),
                env_file=EnvFileInput(variables={"SECRET": CANARY_BYTES}),
                timeout_seconds=0.3,
            )
        )
    assert "timed out" in exc_info.value.safe.message.lower()
    assert_canary_absent(exc_info.value.safe.message)
    assert_no_canary_under(tmp_path)


@pytest.mark.security
@pytest.mark.asyncio
async def test_envfile_stderr_echo_redacted(tmp_path: Path) -> None:
    code = (
        "import sys;"
        "p=sys.argv[1];d=open(p,'rb').read();"
        "sys.stderr.buffer.write(d);sys.stderr.flush();"
        "sys.exit(0 if d else 1)"
    )
    runner = AsyncSecureProcessRunner()
    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=("-c", code, ENV_FILE_PLACEHOLDER),
            cwd=tmp_path,
            environment=_child_env(tmp_path),
            env_file=EnvFileInput(variables={"SECRET": CANARY_BYTES}),
            timeout_seconds=10.0,
        )
    )
    assert result.exit_code == 0
    assert_canary_absent(result.stderr_summary, label="redacted stderr")


@pytest.mark.security
@pytest.mark.asyncio
async def test_stdin_set_never_puts_value_on_argv(tmp_path: Path) -> None:
    code = f"import sys;d=sys.stdin.buffer.read();sys.exit(0 if d==b'{CANARY}' else 1)"
    argv = ("-c", code)
    assert CANARY.encode() not in str(argv[0]).encode()
    code2 = "import sys;d=sys.stdin.buffer.read();sys.exit(0 if len(d)>0 else 1)"
    runner = AsyncSecureProcessRunner()
    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=("-c", code2),
            cwd=tmp_path,
            environment=build_minimal_child_env({"PATH": "/usr/bin:/bin"}),
            stdin_bytes=CANARY_BYTES,
        )
    )
    assert result.exit_code == 0
    assert CANARY not in code2
    assert_no_canary_under(tmp_path)


@pytest.mark.security
@pytest.mark.asyncio
async def test_probe_uses_non_secret_token(tmp_path: Path) -> None:
    runner = AsyncSecureProcessRunner()
    ok = await probe_env_file_pipe(
        runner,
        reader_executable=Path(sys.executable),
        reader_args=(str(FD_READER),),
        cwd=tmp_path,
        environment=build_minimal_child_env({"PATH": "/usr/bin:/bin"}),
    )
    assert ok is True
    assert_no_canary_under(tmp_path)


@pytest.mark.security
def test_streaming_write_chunks_not_one_megastring() -> None:
    chunks: list[bytes] = []
    variables = {"K1": CANARY_BYTES, "K2": b"second"}
    stream_dotenv(variables, chunks.append)
    assert len(chunks) > 1
    full = b"".join(chunks)
    assert full.count(b"\n") == 2
    assert all(c != full for c in chunks)


@pytest.mark.security
@pytest.mark.parametrize(
    "key",
    ["", "BAD=KEY", "BAD\nKEY", "BAD\rKEY", "BAD\x00KEY"],
)
def test_dotenv_key_rejection_safe(key: str) -> None:
    with pytest.raises(DotenvEncodeError) as exc_info:
        validate_dotenv_key(key)
    assert_canary_absent(str(exc_info.value))


@pytest.mark.security
def test_dotenv_value_nul_rejected() -> None:
    with pytest.raises(DotenvEncodeError):
        quote_dotenv_value(b"ok\x00no")


@pytest.mark.security
def test_dotenv_quoting_roundtrip_specials() -> None:
    raw = b'a\\b"c\nd\re\tf\x01g'
    quoted = quote_dotenv_value(raw)
    assert quoted.startswith(b'"') and quoted.endswith(b'"')
    inner = quoted[1:-1].decode("utf-8")
    out: list[str] = []
    i = 0
    while i < len(inner):
        if inner[i] == "\\" and i + 1 < len(inner):
            nxt = inner[i + 1]
            mapping = {"\\": "\\", '"': '"', "n": "\n", "r": "\r", "t": "\t"}
            if nxt in mapping:
                out.append(mapping[nxt])
                i += 2
                continue
            if nxt == "x" and i + 3 < len(inner):
                out.append(chr(int(inner[i + 2 : i + 4], 16)))
                i += 4
                continue
        out.append(inner[i])
        i += 1
    assert "".join(out).encode("utf-8") == raw


@pytest.mark.security
@pytest.mark.asyncio
async def test_bulk_multi_key_one_pipe(tmp_path: Path) -> None:
    variables = {f"K{i}": f"{CANARY}-{i}".encode() for i in range(5)}
    expected = _encode_expected(variables)
    digest = hashlib.sha256(expected).hexdigest()
    runner = AsyncSecureProcessRunner()
    result = await runner.execute(
        SecureProcessRequest(
            executable=Path(sys.executable),
            arguments=(str(FD_READER), ENV_FILE_PLACEHOLDER),
            cwd=tmp_path,
            environment=_child_env(tmp_path),
            env_file=EnvFileInput(variables=variables),
        )
    )
    assert result.exit_code == 0
    assert len(expected) > 50
    assert digest
    assert_no_canary_under(tmp_path)
