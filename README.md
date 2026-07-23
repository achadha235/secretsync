# SecretSync

Local-first CLI that pushes secrets from your vault-backed environment into **GitHub Actions**, **Vercel**, and **SST** using a checked-in YAML file — without pasting values into Slack or dashboards.

## Quickstart

Requires [uv](https://docs.astral.sh/uv/). Assumes `secretsync` is on PyPI.

```bash
# Scaffold config + 1Password-style env template
uvx secretsync init

# Edit secretsync.yaml (repo/project/stage names), then inject env:
# Option A — 1Password
op run --env-file=.env.secretsync.tpl -- uvx secretsync validate
op run --env-file=.env.secretsync.tpl -- uvx secretsync plan
op run --env-file=.env.secretsync.tpl -- uvx secretsync apply --yes

# Option B — copy the template and export locally
cp .env.secretsync.tpl .env.secretsync
# fill values, then:
set -a && source .env.secretsync && set +a
uvx secretsync health
uvx secretsync apply --yes
```

Limit work to one environment so you do not need prod vault access for staging:

```bash
uvx secretsync --deployment github-staging plan
uvx secretsync --deployment github-staging apply --yes
uvx secretsync --destination vercel plan
```

`--deployment` and `--destination` are repeatable; when both are set, only the intersection runs.

## Commands

| Command | Purpose |
|---|---|
| `secretsync init` | Create `secretsync.yaml` + `.env.secretsync.tpl` |
| `secretsync validate` | Check config + required env presence |
| `secretsync plan` | Value-free always-write plan (`--prune` lists remotes and plans deletes) |
| `secretsync apply` | Resolve and write secrets (`--prune` also deletes orphans) |
| `secretsync health` | Auth/reachability checks (skips unset tokens) |
| `secretsync ui` | Interactive Textual review/apply |
| `secretsync connectors` | List built-in connectors |

Useful flags: `--config`, `--format json`, `--verbose`, `--quiet`, `--deployment`, `--destination`, `--prune`.

With `--prune`, SecretSync lists remote secret **names** at plan time and treats YAML as the full desired inventory for each destination scope — remote secrets not listed in the config are planned for deletion (including secrets never created by SecretSync). Without `--prune`, apply is put-only.

Runs write a value-free trail under `.secretsync/audit.log` (gitignored).

## Learn more

How the pieces fit together (including the SST env-file pipe): [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

MIT — see [LICENSE](LICENSE).
