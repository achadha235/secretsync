#!/usr/bin/env python3
"""Sleep forever so the parent times out (killed by runner)."""

from __future__ import annotations

import time


def main() -> int:
    time.sleep(3600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
