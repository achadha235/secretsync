#!/usr/bin/env python3
"""Close inherited fd 3 immediately so the parent writer hits EPIPE."""

from __future__ import annotations

import os
import time


def main() -> int:
    with __import__("contextlib").suppress(OSError):
        os.close(3)
    time.sleep(0.2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
