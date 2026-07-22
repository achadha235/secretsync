# SecretSync

Declarative, secure secret delivery from process environment to GitHub Actions, Vercel, and SST.

SecretSync is local-first: a vault runner such as `op run` injects values into the process environment, then SecretSync compiles a checked-in YAML declaration into destination mutations. **MVP uses always-write** — plans describe intended writes and do not detect drift.

> Security: plaintext secrets move only through process memory, authenticated provider APIs, or inherited one-time pipes. Resolved values are never persisted in config, plans, logs, or temporary files.

## Status (M0–M5)

| Capability | Status |
|---|---|
| Config schema, compose, validate, plan | Implemented |
| Environment source | Implemented |
| Click CLI shell | Implemented |
| Destination framework + apply coordinator | Implemented (M2) |
| Fake connectors (`fake-batch`, `fake-individual`) | Implemented |
| GitHub Actions secrets (repo + environment) | Implemented (M3) |
| Vercel env bulk upsert (`/v10/.../env?upsert=true`) | Implemented (M3) |
| SST secure runner (env-file pipe + stdin set) | Implemented (M4) |
| Textual TUI | Implemented (M5) |

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- For SST apply: `sst` (preferred) or `bunx` on `PATH`, plus AWS credentials in the environment

## Setup

```bash
uv sync --all-groups
uv run secretsync --help
```

## Quickstart

Configuration contains environment variable **names** (or vault references in a sibling `.env`), never resolved plaintext.

```bash
# Copy examples/.env.example and replace placeholders, or use vault refs:
# YB_DATABASE_URL="op://..."
# GITHUB_TOKEN="op://..."

cp examples/.env.example .env
# SecretSync does not auto-load .env — inject via shell or op run:
set -a && source .env && set +a
uv run secretsync --config examples/secretsync.yaml validate
uv run secretsync --config examples/secretsync.yaml plan

op run --env-file=.env -- secretsync --config examples/secretsync.yaml apply --yes
```

`examples/.env.example` lists every env key the example YAMLs need so `validate`/`plan` succeed with placeholders. `apply` still needs real provider credentials (and for SST a real project directory).

`examples/secretsync.github-vercel.yaml` covers GitHub + Vercel only. The full three-destination example is `examples/secretsync.yaml`.

**Provider notes**
- Vercel writes affect **future** deployments only; SecretSync does not trigger a redeploy.
- SST secret changes require a later `sst deploy` (unless `sst dev` is active); SecretSync does not deploy.
- SST bulk load uses an inherited anonymous pipe (`/proc/self/fd/3` on Linux, `/dev/fd/3` on macOS) — never a plaintext temp file. On Windows, M4 uses per-secret `sst secret set` via stdin only.

Without `op run`, export the required variables in your shell and run the same commands.
Group options (`--config`, `--format`) must appear before the subcommand.

### Fake connectors (framework demos)

```bash
export YB_DATABASE_URL=... STRIPE_SECRET_KEY=... API_TOKEN=...
uv run secretsync --config tests/fixtures/fake_apply.yaml apply --yes
```

### Opt-in provider smoke tests

```bash
export SECRETSYNC_SMOKE=1
export GITHUB_TOKEN=... VERCEL_TOKEN=...
# plus smoke-specific repo/project/stage env vars documented in tests/smoke/
uv run pytest -m smoke
```

Default CI runs `pytest` without smoke (no credentials required).

## Commands

| Command | Purpose |
|---|---|
| `secretsync validate` | Parse, compose, check env presence; no remote writes |
| `secretsync plan` | Value-free always-write plan |
| `secretsync apply` | Resolve values and apply via registered connectors |
| `secretsync ui` | Textual review/apply UI (never shows secret values) |
| `secretsync connectors` | List built-in connector IDs |

Exit codes: `0` ok, `2` config/usage, `3` missing environment, `4` connector validation, `5` partial apply, `6` all failed, `130` interrupted.

### Textual TUI (`secretsync ui`)

Keyboard-first screens: configuration → plan → confirm → execution → results. Same `AppServices` path as Click (no second apply implementation). Status uses text labels (e.g. `OK` / `FAIL`), not color alone. Results can export a value-free JSON report and retry failed mutations. Use `secretsync apply --yes --format json` when you need machine-readable output without the TUI (`--format json ui` is rejected).

**Accessibility checklist**
- Full keyboard path through all screens (Tab / Enter / bindings)
- Status never conveyed by color alone
- Primary actions remain reachable without a pointer

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
tests/integration/  connector HTTP/process tests
tests/contract/     destination protocol / batching contracts
tests/security/     no-tempfile / canary process tests
tests/smoke/        opt-in live provider checks
tests/fixtures/     golden config and error fixtures
```

## License

See repository metadata.
