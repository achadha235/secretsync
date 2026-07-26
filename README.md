# SecretSync

Local-first CLI that pushes secrets from your vault-backed environment into deployments using a checked-in YAML file — without pasting values into Slack or dashboards.

> ⚠️ **Disclaimer: This software is pre-alpha and under development. Use with caution.**

## Motivation

Vaults solve storage, rotation, access control, and audit. The gap is **delivery**: getting the same secret into GitHub Actions, Vercel, and SST without paste-into-Slack, clipboard history, or hand-copying the same key into three dashboards — and without half-rotated deploys when one destination is forgotten.

SecretSync is a thin CLI for that gap. You declare routing in a checked-in YAML file (reviewable in PRs; plaintext stays out of git), inject values from your vault into the process environment (`op run`, Doppler, etc.), and push. Destination quirks — GitHub repo/environment/org scopes, Vercel deployment targets, SST stages — stay behind connectors so the config stays simple.

Full secrets platforms (Infisical and similar) can do this and more, but they are overkill when you already trust a vault and only need to say which names land where. Plaintext should only move through process memory, authenticated provider APIs, or one-shot env injection — never config, plans, logs, or temp files.

## Quickstart

```bash
## Install with uv
uv tool install secretsync-cli

# Scaffold config + 1Password-style env template
secretsync init
```

### Setup

```bash
# .env.tpl — vault refs injected into the process env (e.g. via `op run`)
GITHUB_TOKEN="op://vault/github/token"   # connector auth
API_KEY="op://vault/app/api-key"         # secret value SecretSync reads
```

```yaml
# secretsync.yaml
version: 1
changeDetection: always-write

# Logical secret ids → which process env var holds the plaintext value
secrets:
  apiKey:
    env: API_KEY # reads os.environ["API_KEY"]

# Non-secret configuration (same shape; never written to a secure store as a secret)
variables:
  logLevel:
    env: LOG_LEVEL

# Named bundles of secrets/variables to ship together
sets:
  production:
    include: [apiKey, logLevel]

# Where values can be written (connector + auth)
destinations:
  github:
    connector: github-actions
    # Either repository: owner/name …
    repository: owner/repo
    # … or organization: + repository: name (not both with owner/name)
    # organization: owner
    # repository: repo
    auth:
      tokenEnv: GITHUB_TOKEN # reads os.environ["GITHUB_TOKEN"] for API auth

# Concrete pushes: which set → which destination, under what remote names
deployments:
  - name: github-production
    set: production
    destination: github
    scope:
      kind: environment
      environment: production
    secrets:
      # logical id → remote secret name in GitHub Actions
      apiKey: API_KEY
    variables:
      # logical id → remote variable name (Actions Variables API)
      logLevel: LOG_LEVEL

  # Org secrets/variables: org is destination.organization, or the owner of
  # repository (acme from acme/web). Org-only destinations work for this scope.
  # Token needs admin:org (classic PAT). visibility defaults to private.
  - name: github-org
    set: production
    destination: github
    scope:
      kind: organization
      visibility: private # all | private | selected (+ selected_repository_ids)
    secrets:
      apiKey: API_KEY
    variables:
      logLevel: LOG_LEVEL
```

Kind is declared once under `secrets` or `variables`. Connectors map kind to the provider primitive (GitHub secrets vs variables APIs; Vercel `type: sensitive` vs `encrypted`). SST supports secrets only — non-secret SST config belongs in code as [Linkables](https://sst.dev/docs/component/linkable/).

> **Breaking:** Vercel `scope.sensitive` is removed. Put sensitive values under `deployment.secrets` and plaintext under `deployment.variables`.
>
> **Breaking:** Vercel destinations require `teamId`. Project env deployments need `scope.kind: environment` (and destination `project`). Team shared env uses `scope.kind: shared-environment` with optional `scope.projects`.

Vercel destination modes (selected by `scope.kind`):

```yaml
destinations:
  vercel:
    connector: vercel
    teamId: team_xyz          # required
    project: prj_abc          # optional; required for kind: environment
    auth:
      tokenEnv: VERCEL_TOKEN

deployments:
  - name: vercel-production
    set: production
    destination: vercel
    scope:
      kind: environment
      targets: [production]
    secrets:
      apiKey: API_KEY
  - name: vercel-shared
    set: production
    destination: vercel
    scope:
      kind: shared-environment
      targets: [production]
      projects: [prj_abc, prj_def]  # optional link set
    secrets:
      sharedSecret: SHARED_SECRET
```

## Deploy secrets

```bash
# After editing secretsync.yaml (repo/project/stage names) and .env.tpl (secret references),
# then inject env and run command:

# Example with 1Password CLI:

# Run a health check to ensure secretsync is authenticated
op run --env-file=.env.tpl -- secretsync health

# Validate and plan a config
op run --env-file=.env.tpl -- secretsync validate ## makes sure the config is valid
op run --env-file=.env.tpl -- secretsync plan ## shows you what changes will be made

## Apply changes into your destination
op run --env-file=.env.tpl -- secretsync apply ## applies the changes
```

You can also target a single deployment or destination

```bash
op run --env-file=.env.tpl -- secretsync --deployment github-production plan
op run --env-file=.env.tpl -- secretsync --deployment github-production apply --yes
op run --env-file=.env.tpl -- secretsync --destination github plan
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

With `--prune`, SecretSync lists remote names at plan time (secrets and variables separately) and treats YAML as the full desired inventory for each destination scope + kind — remote entries not listed in the config are planned for deletion. Without `--prune`, apply is put-only.

## Supported Destinations

We currently support these destinations.

- [GitHub Actions](https://github.com/features/actions)
- [Vercel](https://vercel.com/)
- [SST](https://sst.dev/)

## Audit

`secretsync` writes an audit trail under `.secretsync/audit.log` so you can keep track of what changed when. The `.secretsync` folder can safely be checked into source control.

## License

MIT — see [LICENSE](LICENSE).
