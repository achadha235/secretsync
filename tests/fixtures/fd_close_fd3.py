#!/usr/bin/env python3
"""Open the env-file path then close early so the parent writer hits EPIPE."""

from __future__ import annotations

import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 2
    path = argv[1]
    # Open briefly so the writer unblocks, then close without draining — fat writes EPIPE.
    with open(path, "rb") as handle:
        handle.read(1)
    time.sleep(0.5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
