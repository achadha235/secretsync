# SecretSync

Local-first CLI that pushes secrets from your vault-backed environment into deployments using a checked-in YAML file — without pasting values into Slack or dashboards.

> ⚠️ **Disclaimer: This software is pre-alpha and under development. Use with caution.**

## Motivation

Vaults solve storage, rotation, access control, and audit. The gap is **delivery**: getting the same secret into GitHub Actions, Vercel, and SST without paste-into-Slack, clipboard history, or hand-copying the same key into three dashboards — and without half-rotated deploys when one destination is forgotten.

SecretSync is a thin CLI for that gap. You declare routing in a checked-in YAML file (reviewable in PRs; plaintext stays out of git), inject values from your vault into the process environment (`op run`, Doppler, etc.), and push. Destination quirks — GitHub repo/environment/org scopes, Vercel deployment targets, SST stages — stay behind connectors so the config stays simple.

Full secrets platforms (Infisical and similar) can do this and more, but they are overkill when you already trust a vault and only need to say which names land where. Plaintext should only move through process memory, authenticated provider APIs, or one-shot env injection — never config, plans, logs, or temp files.

## Quickstart

```bash
# Scaffold config + 1Password-style env template
uvx secretsync init

# Edit secretsync.yaml (repo/project/stage names) and .env.tpl (secret references), then inject env:
# Example with 1Password CLI
op run --env-file=.env.tpl -- uvx secretsync validate
op run --env-file=.env.tpl -- uvx secretsync plan
op run --env-file=.env.tpl -- uvx secretsync apply --yes

# Run a health check to ensure secretsync is authenticated
op run --env-file=.env.tpl -- uvx secretsync health

## Plan and apply changes into your destination
op run --env-file=.env.tpl -- uvx secretsync apply --yes
```

You can also target a single deployent or destination

```bash
op run --env-file=.env.tpl -- uvx secretsync --deployment github-staging plan
op run --env-file=.env.tpl -- uvx secretsync --deployment github-staging apply --yes
op run --env-file=.env.tpl -- uvx secretsync --destination vercel plan
```

`--deployment` and `--destination` are repeatable; when both are set, only the intersection runs.

> 👉 While this example uses the 1Password CLI and vault, `secretsync` with any system that can securely set secrets in your environment (Doppler, mise, Infisical etc.)

## Commands

| Command                 | Purpose                                                                      |
| ----------------------- | ---------------------------------------------------------------------------- |
| `secretsync init`       | Initialize `secretsync.yaml` + `.env.tpl` template                           |
| `secretsync validate`   | Check config + required env presence                                         |
| `secretsync plan`       | Plan the necessary changes (`--prune` lists remotes and plans deletes)       |
| `secretsync apply`      | Resolve the plan and write secrets (`--prune` also deletes orphaned secrets) |
| `secretsync health`     | Auth/reachability checks (skips unset tokens)                                |
| `secretsync ui`         | Interactive Textual review/apply                                             |
| `secretsync connectors` | List built-in connectors                                                     |

Useful flags: `--config`, `--format json`, `--verbose`, `--quiet`, `--deployment`, `--destination`, `--prune`.

With `--prune`, SecretSync lists remote secret names at plan time and treats YAML as the full desired inventory for each destination scope — remote secrets not listed in the config are planned for deletion (including secrets never created by SecretSync). Without `--prune`, apply is put-only.

## Supported Destinations

We currently support these destinations.

- [GitHub Actions](https://github.com/features/actions)
- [Vercel](https://vercel.com/)
- [SST](https://sst.dev/)

## Audit

`secretsync` writes an audit trail under `.secretsync/audit.log` so you can keep track of what changed when. The `.secretsync` folder can safely be checked into source control.

## License

MIT — see [LICENSE](LICENSE).
