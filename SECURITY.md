# Security

## Reporting a vulnerability

Please report security issues privately to the repository maintainers (GitHub Security Advisories preferred when enabled). Do not open public issues that include real secret values or exploit PoCs against third-party accounts.

## Guarantees (MVP)

SecretSync is designed so resolved secrets:

- Are **not** stored in YAML, plans, JSON reports, or TUI widget state
- Are **not** written to plaintext temporary files for SST delivery
- Are **not** placed on process argv for SST `secret set` (stdin) or `secret load` (fd path only)
- Are **not** copied wholesale into child environments (allow-list only)
- Are scrubbed from mutable buffers after apply where possible

### Canary suite

Default CI runs `@pytest.mark.security` tests that inject `SECRET_CANARY_*` values and assert absence from stdout, stderr, JSON, exceptions, tmp trees, and argv where applicable. See `tests/security/`.

### Env-file pipe

SST bulk delivery uses an anonymous pipe inherited as fd 3. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Security/correctness coverage lives in `tests/security/test_envfile_pipe.py`.

## What we do not claim

- Host hardening against core dumps, swap, or compromised root
- Protection if the vault or CI runner is already compromised
- Drift detection or automatic rollback of partial provider writes

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
