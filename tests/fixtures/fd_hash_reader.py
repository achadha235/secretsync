#!/usr/bin/env python3
"""Read fd path, hash contents, never echo secret bytes."""

from __future__ import annotations

import hashlib
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: fd_hash_reader.py <fd-path>", file=sys.stderr)
        return 2
    with open(argv[1], "rb") as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()
    print(f"bytes={len(data)} sha256={digest}")
    return 0 if data else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
