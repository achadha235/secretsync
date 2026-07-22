#!/usr/bin/env python3
"""Read an inherited env-file descriptor path and exit 0 if any bytes were received.

Does not echo secret contents — only reports byte length on stdout.
"""

from __future__ import annotations

import hashlib
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: fd_reader.py <fd-path>", file=sys.stderr)
        return 2
    path = argv[1]
    with open(path, "rb") as handle:
        data = handle.read()
    digest = hashlib.sha256(data).hexdigest()[:16]
    print(f"bytes={len(data)} sha256_16={digest}")
    return 0 if data else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
