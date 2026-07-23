#!/usr/bin/env python3
"""Exit immediately without reading fd 3 (forces EPIPE on writer)."""

from __future__ import annotations

import sys


def main() -> int:
    print("early-exit", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
