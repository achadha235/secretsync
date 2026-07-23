"""Append-only value-free audit log under .secretsync/."""

from __future__ import annotations

import getpass
import hashlib
import os
import socket
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from loguru import logger

from secretsync.domain.models import JsonValue

HASH_FILE = "config.sha256"
AUDIT_FILE = "audit.log"


def audit_dir_for(config_path: Path | None, *, cwd: Path | None = None) -> Path:
    base = (cwd or Path.cwd()).resolve()
    if config_path is not None and config_path.exists():
        return config_path.resolve().parent / ".secretsync"
    return base / ".secretsync"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def format_scope(scope: Mapping[str, JsonValue]) -> str:
    if not scope:
        return "-"
    return ",".join(f"{k}:{v}" for k, v in sorted(scope.items()))


@lru_cache(maxsize=1)
def actor_context() -> str:
    """Self-reported machine/operator identity (not tamper-proof)."""
    return " ".join(
        [
            f"user={_safe_user()}",
            f"host={_safe_host()}",
            f"ip={_client_ip()}",
            f"mac={_mac()}",
            f"pid={os.getpid()}",
        ]
    )


def new_run_id() -> str:
    return uuid.uuid4().hex[:12]


def record_audit(
    *,
    command: str,
    config_path: Path | None = None,
    exit_code: int | None = None,
    extra: str = "",
    cwd: Path | None = None,
    run_id: str | None = None,
) -> Path:
    """Append one command audit line; update config hash sidecar. Returns audit.log path."""
    root = audit_dir_for(config_path, cwd=cwd)
    root.mkdir(parents=True, exist_ok=True)
    hash_path = root / HASH_FILE
    audit_path = root / AUDIT_FILE

    if config_path is not None and config_path.is_file():
        current = sha256_file(config_path)
        config_ref = str(config_path.resolve())
    else:
        current = "-"
        config_ref = "-"

    changed = "first"
    if current != "-":
        if hash_path.is_file():
            previous = hash_path.read_text(encoding="utf-8").strip()
            changed = "yes" if previous != current else "no"
        hash_path.write_text(current + "\n", encoding="utf-8")

    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [
        stamp,
        "event=command",
        f"cmd={command}",
        f"run={run_id or '-'}",
        actor_context(),
        f"config={config_ref}",
        f"sha256={current}",
        f"config_changed={changed}",
    ]
    if exit_code is not None:
        parts.append(f"exit={exit_code}")
    if extra:
        parts.append(extra)
    _append_line(audit_path, " ".join(parts))
    return audit_path


def record_mutation_audit(
    *,
    config_path: Path | None,
    run_id: str,
    destination_id: str,
    connector_id: str,
    deployment_id: str,
    op: str,
    name: str,
    scope: Mapping[str, JsonValue],
    status: str,
    effect: str | None,
    correlation_id: str,
    error_code: str | None = None,
    cwd: Path | None = None,
) -> Path:
    """Append one value-free per-secret mutation line."""
    root = audit_dir_for(config_path, cwd=cwd)
    root.mkdir(parents=True, exist_ok=True)
    audit_path = root / AUDIT_FILE
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [
        stamp,
        "event=mutation",
        f"run={run_id}",
        actor_context(),
        f"dest={destination_id}",
        f"connector={connector_id}",
        f"deployment={deployment_id}",
        f"op={op}",
        f"name={name}",
        f"scope={format_scope(scope)}",
        f"status={status}",
        f"effect={effect or '-'}",
        f"correlation={correlation_id}",
        f"error={error_code or '-'}",
    ]
    _append_line(audit_path, " ".join(parts))
    return audit_path


def _append_line(audit_path: Path, line: str) -> None:
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    logger.debug("audit appended to {}", audit_path)


def _safe_user() -> str:
    try:
        return getpass.getuser() or "-"
    except Exception:  # noqa: BLE001 — audit must never fail the command
        return "-"


def _safe_host() -> str:
    try:
        return socket.gethostname() or "-"
    except Exception:  # noqa: BLE001
        return "-"


def _mac() -> str:
    node = uuid.getnode()
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


def _client_ip() -> str:
    # ponytail: SSH client IP identifies remote operator; else outbound iface
    ssh = os.environ.get("SSH_CONNECTION", "").split()
    if ssh:
        return ssh[0]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "-"
