#!/usr/bin/env python3
"""Echo argv and a subset of env keys to a path; used to prove no secret leaks."""

from __future__ import annotations

import json
import os
import sys


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        return 2
    out = argv[1]
    env_path = argv[2]
    keys = ("PATH", "HOME", "YB_DATABASE_URL", "STRIPE_SECRET_KEY")
    payload = {
        "argv": argv[2:],
        "env": {k: os.environ.get(k) for k in keys},
    }
    # Drain the named pipe for length only — never echo contents.
    try:
        with open(env_path, "rb") as handle:
            payload["env_file_len"] = len(handle.read())
    except OSError:
        payload["env_file_len"] = None
    with open(out, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
