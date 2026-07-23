# Changelog

All notable changes to this project are documented in this file.

## 0.1.0 — MVP

First MVP release of SecretSync.

### Highlights

- Declarative YAML config: secrets, sets, destinations, deployments
- Always-write planning (no drift detection in MVP)
- Environment source with presence/empty/NUL checks
- Click CLI: `validate`, `plan`, `apply`, `ui`, `connectors`
- Textual review/apply TUI (keyboard-first; never renders secret values)
- Destinations: GitHub Actions (repo + environment), Vercel (`/v10/.../env?upsert=true`), SST (env-file pipe + stdin set)
- Security canary suite; SST secrets via inherited fd 3 — never plaintext tempfiles

### Important semantics

- **Always-write:** every planned put is written on apply. Plans never contain values.
- **Vercel:** writes affect **future** deployments only; SecretSync does not redeploy.
- **SST:** secret changes require a later `sst deploy` (unless `sst dev` is active); SecretSync does not deploy.

### Packaging

- Wheel + sdist via `uv build`
- Release tags `v*` publish GitHub Release artifacts with `SHA256SUMS` and (when configured) PyPI via Trusted Publishing
