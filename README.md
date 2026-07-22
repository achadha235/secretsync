# SecretSync

Declarative, secure secret delivery from process environment to GitHub Actions, Vercel, and SST.

SecretSync is local-first: a vault runner such as `op run` injects values into the process environment, then SecretSync compiles a checked-in YAML declaration into destination mutations. **MVP uses always-write** — plans describe intended writes and do not detect drift.

> Security: plaintext secrets move only through process memory, authenticated provider APIs, or inherited one-time pipes. Resolved values are never persisted in config, plans, logs, or temporary files.

## Status (M0 / M1 / M2)

| Capability | Status |
|---|---|
| Config schema, compose, validate, plan | Implemented |
| Environment source | Implemented |
| Click CLI shell | Implemented (`ui` stubbed until M5) |
| Destination framework + apply coordinator | Implemented (M2) |
| Fake connectors (`fake-batch`, `fake-individual`) | Implemented — prove connector-owned batching |
| Real destinations (GitHub, Vercel, SST) | Planned (M3–M4) |
| Textual TUI | Planned (M5) |

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync --all-groups
uv run secretsync --help
```

## Quickstart

Configuration contains environment variable **names** (or vault references in a sibling `.env`), never resolved plaintext.

```bash
# .env contains references, not plaintext
# YB_DATABASE_URL="op://..."
# GITHUB_TOKEN="op://..."

op run --env-file=.env -- secretsync --config examples/secretsync.yaml validate
op run --env-file=.env -- secretsync --config examples/secretsync.yaml plan
op run --env-file=.env -- secretsync --config examples/secretsync.yaml --format json plan
```

Apply against real GitHub/Vercel/SST destinations lands in M3/M4. Until then, exercise apply with the fake connectors:

```bash
export YB_DATABASE_URL=... STRIPE_SECRET_KEY=... API_TOKEN=...
uv run secretsync --config tests/fixtures/fake_apply.yaml apply --yes
```

Without `op run`, export the required variables in your shell and run the same commands.
Group options (`--config`, `--format`) must appear before the subcommand.

## Commands

| Command | Purpose |
|---|---|
| `secretsync validate` | Parse, compose, check env presence; no remote writes |
| `secretsync plan` | Value-free always-write plan |
| `secretsync apply` | Resolve values and apply via registered connectors |
| `secretsync ui` | Textual UI (M5) |
| `secretsync connectors` | List built-in connector IDs |

Exit codes: `0` ok, `2` config/usage, `3` missing environment, `4` connector validation, `5` partial apply, `6` all failed, `130` interrupted.

## Quality gates

```bash
uv sync --frozen --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

CI runs the same gates on every pull request via GitHub Actions (`.github/workflows/ci.yml`).

## Layout

```text
src/secretsync/     application package
examples/           sample secretsync.yaml
tests/unit/         unit tests
tests/contract/     destination protocol / batching contracts
tests/fixtures/     golden config and error fixtures
```

## License

See repository metadata.
