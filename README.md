# SecretSync

**SecretSync** delivers secrets from your local vault-backed environment into GitHub Actions, Vercel, and SST — from a checked-in YAML declaration, without pasting values into chat tools or provider dashboards.

> Security: plaintext secrets move only through process memory, authenticated provider APIs, or inherited one-time pipes. Resolved values are never persisted in config, plans, logs, or temporary files.

## The problem

Secrets are often fine **at rest**. 1Password, cloud KMS, and vault products lock them down well.

The painful part is **moving them to where they are used**:

- Pasting keys into Slack or tickets
- Browser password fields and clipboard managers that retain history
- Copying the same Stripe key into GitHub, Vercel, and SST by hand
- Rotation that updates the backend but forgets the frontend env — and ships a half-rotated key

You already trust a vault. You should not need a second platform just to push names and scopes into the three places your app already deploys.

## Why not a full secrets platform?

Products like Infisical (and similar) are capable, but for many small and mid-size projects they are **overkill**: SDKs, connectors, OAuth apps, agents, and ongoing ops — when you already use **1Password / `op run`** (or plain env injection) and only need to **declare** which secrets land where.

SecretSync stays local-first: vault injects the process environment; SecretSync compiles YAML into destination mutations.

## What SecretSync does

1. You check in `secretsync.yaml` with **names and scopes** (never plaintext values).
2. A vault runner (or your shell) injects env vars for this process.
3. `validate` / `plan` / `apply` (or `ui`) write every declared target (**always-write** in MVP).
4. The same logical secret can be renamed per destination — one rotation, many sinks.

Rotation becomes: change the vault item, re-run apply, done.

## Security model (short)

| Channel | How secrets move |
|---|---|
| Config / plans / JSON / TUI | Names and scopes only — **never values** |
| GitHub / Vercel | Authenticated HTTPS APIs; no request-body logging |
| SST bulk load | Anonymous pipe → inherit **fd 3** → stream dotenv — **never a plaintext tempfile** |
| SST single set | Value on **stdin** only (never argv) |

Child processes get a **minimal** environment (`PATH`, `HOME`, locale, `AWS_*`) — not your full secret-laden parent env.

Details: [SECURITY.md](SECURITY.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Status (M0–M6)

| Capability | Status |
|---|---|
| Config, compose, validate, plan | Implemented |
| Environment source | Implemented |
| Click CLI + Textual TUI | Implemented |
| Destination framework + apply | Implemented |
| GitHub Actions, Vercel, SST | Implemented |
| Security canaries + env-file pipe tests | Implemented (M6) |
| Packaging, checksums, release workflow | Implemented (M6) |

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- For SST apply: `sst` (preferred) or `bunx` on `PATH`, plus AWS credentials in the environment

## Install

```bash
# From source (development)
uv sync --all-groups
uv run secretsync --help

# From a release wheel (after publish)
pip install secretsync
# or: uvx secretsync --help
```

## Quickstart

Configuration contains environment variable **names** (or vault references in a sibling `.env`), never resolved plaintext.

```bash
cp examples/.env.example .env
# Replace placeholders, or use op:// vault refs for `op run`

# SecretSync does not auto-load .env — inject via shell or 1Password:
set -a && source .env && set +a
uv run secretsync --config examples/secretsync.yaml validate
uv run secretsync --config examples/secretsync.yaml plan

op run --env-file=.env -- secretsync --config examples/secretsync.yaml apply --yes
uv run secretsync --config examples/secretsync.yaml ui
```

`examples/.env.example` lists every env key the example YAMLs need so `validate`/`plan` succeed with placeholders. `apply` still needs real provider credentials (and for SST a real project directory).

| Example | Destinations |
|---|---|
| `examples/secretsync.yaml` | GitHub + Vercel + SST |
| `examples/secretsync.github-vercel.yaml` | GitHub + Vercel only |

**Provider notes**

- Vercel writes affect **future** deployments only; SecretSync does not trigger a redeploy.
- SST secret changes require a later `sst deploy` (unless `sst dev` is active); SecretSync does not deploy.
- SST bulk load uses `/proc/self/fd/3` (Linux) or `/dev/fd/3` (macOS). On Windows, M4 uses per-secret stdin set only.

Group options (`--config`, `--format`) must appear before the subcommand.

### Fake connectors (framework demos)

```bash
export YB_DATABASE_URL=... STRIPE_SECRET_KEY=... API_TOKEN=...
uv run secretsync --config tests/fixtures/fake_apply.yaml apply --yes
```

### Opt-in provider smoke tests

```bash
export SECRETSYNC_SMOKE=1
export GITHUB_TOKEN=... SECRETSYNC_SMOKE_GITHUB_REPO=owner/repo
export VERCEL_TOKEN=... SECRETSYNC_SMOKE_VERCEL_PROJECT=...
# optional: SECRETSYNC_SMOKE_VERCEL_TEAM_ID
export SECRETSYNC_SMOKE_SST_DIR=/path/to/sst/app
# optional: SECRETSYNC_SMOKE_SST_STAGE SECRETSYNC_SMOKE_SST_EXECUTABLE
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

`--format json ui` is rejected — use `apply --yes --format json` for machine-readable output.

### Textual TUI

Keyboard-first: configuration → plan → confirm → execution → results. Same application services as Click. Status uses text labels (`OK` / `FAIL` / `RUN`), not color alone. Results can export a value-free JSON report and retry failed mutations.

## Quality gates

```bash
uv sync --frozen --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest --cov=secretsync --cov-fail-under=80
uv run pytest -m security -q
uv build
```

CI runs these on **ubuntu** and **macos** (see `.github/workflows/ci.yml`). Releases on tags `v*` attach wheel/sdist + `SHA256SUMS` (see `.github/workflows/release.yml`). PyPI publish uses Trusted Publishing — configure the GitHub `release` environment and PyPI trusted publisher once for the repo.

## Docs

| Doc | Contents |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev setup, PR gates, security rules for contributors |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Package layout, apply flow, env-file pipe deep dive |
| [SECURITY.md](SECURITY.md) | Disclosure + canary / pipe guarantees |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Threats, mitigations, residual risks |
| [docs/APPENDIX_C_CHECKLIST.md](docs/APPENDIX_C_CHECKLIST.md) | MVP engineering checklist |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## License

MIT — see [LICENSE](LICENSE).
