# Contributing to SecretSync

Thanks for helping. SecretSync handles real secrets — treat every PR as a security-sensitive change.

## Development setup

```bash
uv sync --all-groups
uv run secretsync --help
uv run pytest -q
```

Python 3.12+ required. Prefer [uv](https://docs.astral.sh/uv/).

## Branching and PRs

- Humans: fork + feature branch; open a PR against `main`.
- Cloud agents: `cursor/<descriptive-name>-fe0a` (lowercase).
- Keep PRs focused. Do not commit `.env`, canaries with real credentials, or `.testagent/` scratch unless agreed.

## Quality gates (must pass)

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest --cov=secretsync --cov-fail-under=80
uv run pytest -m security -q
```

CI also runs on **macos-latest** so fd / env-file pipe behavior is exercised off Linux.

## Security rules for contributors

1. **Never log or render secret values** — not in Click output, Textual widgets, exceptions, or JSON reports.
2. **No plaintext tempfiles** for secret material. SST bulk uses inherited fd 3; single set uses stdin.
3. **New secret channels need canaries** — add `@pytest.mark.security` tests that prove a `SECRET_CANARY_*` string never appears in stdout/stderr/JSON/tmp/argv.
4. **Child env is allow-listed** — do not pass the full parent environ into provider CLIs.
5. Prefer extending [`tests/security/`](tests/security/) over one-off asserts buried in unit tests.

### Running pipe / security tests locally

```bash
uv run pytest -m security -q
uv run pytest tests/security/test_envfile_pipe.py -q
```

Linux and macOS both supported. Windows does not get the fd-3 bulk path (stdin set only).

## Adding a connector

1. Implement the destination protocol in `src/secretsync/destinations/` (see `fake.py`, then a real provider).
2. Register the factory in `application/services.py`.
3. Add contract tests (`tests/contract/`) proving one result per mutation and accurate capabilities.
4. Add HTTP or process integration tests with mocks/fixtures — no live credentials in default CI.
5. Document provider assumptions and redeploy caveats in README / CHANGELOG.

## Releases

1. Update [`CHANGELOG.md`](CHANGELOG.md) and version in `pyproject.toml` / `src/secretsync/__init__.py`.
2. Tag `vX.Y.Z` and push the tag.
3. `.github/workflows/release.yml` builds wheel/sdist, writes `SHA256SUMS`, creates a GitHub Release, and publishes to PyPI via OIDC Trusted Publishing.

**Maintainer one-time setup:** create a GitHub Actions environment named `release`, and configure a PyPI trusted publisher for this repository/workflow.

## Docs to keep in sync

- Problem framing and quickstart: [`README.md`](README.md)
- Architecture / pipe deep dive: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Threat model and Appendix C: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md), [`docs/APPENDIX_C_CHECKLIST.md`](docs/APPENDIX_C_CHECKLIST.md)
