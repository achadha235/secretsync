"""Append-only value-free audit log under .secretsync/."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

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


def record_audit(
    *,
    command: str,
    config_path: Path | None = None,
    exit_code: int | None = None,
    extra: str = "",
    cwd: Path | None = None,
) -> Path:
    """Append one audit line; update config hash sidecar. Returns audit.log path."""
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
        f"cmd={command}",
        f"config={config_ref}",
        f"sha256={current}",
        f"config_changed={changed}",
    ]
    if exit_code is not None:
        parts.append(f"exit={exit_code}")
    if extra:
        parts.append(extra)
    line = " ".join(parts) + "\n"
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(line)
    logger.debug("audit appended to {}", audit_path)
    return audit_path
