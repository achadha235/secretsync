#!/usr/bin/env python3
"""Open the env-file path then sleep so the parent times out (killed by runner)."""

from __future__ import annotations

import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        return 2
    # Unblock the writer, then hang so the runner times out.
    with open(argv[1], "rb") as handle:
        handle.read()
    time.sleep(3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
