# SecretSync architecture

This document describes how SecretSync is structured and how secrets move — especially the SST **env-file pipe**.

## Context

```text
  1Password / vault / shell exports
              |
              v
     process environment
              |
     +--------+--------+
     |                 |
  Click CLI        Textual TUI
     |                 |
     +--------+--------+
              |
         AppServices
              |
    validate -> plan -> apply
              |
     +--------+--------+--------+
     |        |        |        |
   GitHub   Vercel    SST     fakes
   (HTTPS)  (HTTPS)  (process)
```

Both Click and Textual use the same [`AppServices`](../src/secretsync/application/services.py) composition root. There is no second plan/apply implementation.

## Package layout

| Package | Role |
|---|---|
| `config/` | Pydantic YAML schema + loader + set composition |
| `application/` | validate, plan, apply coordinator |
| `sources/` | Environment secret source |
| `destinations/` | Connector protocol, registry, GitHub/Vercel/SST/fakes |
| `infrastructure/` | HTTP client, process runner, dotenv encoder, redaction |
| `presentation/` | Human + versioned JSON renderers (value-free) |
| `tui/` | Textual screens + CSS |
| `cli.py` | Click entry only |

## Always-write planning vs apply

1. **Validate** — parse YAML, compose sets, check env **presence** (no value logging).
2. **Plan** — emit value-free puts (logical id, source env **name**, destination name, scopes).
3. **Confirm** — CLI prompt or TUI confirmation (always-write warning).
4. **Apply** — resolve values late into `bytearray`, call connectors, scrub buffers, build `ApplyReport`.

MVP does not detect drift. `changeDetection: keyed-fingerprint` fails with `UNIMPLEMENTED_CHANGE_DETECTION`.

## Connector boundary

Connectors own batching and provider adaptation. The coordinator groups mutations by destination and deployment, then calls `apply` with `PutMutation` values. Each mutation must receive exactly one result (`applied` / `failed` / `skipped`).

Capabilities are declared in manifests and checked by contract tests.

## Env-file pipe (SST bulk path)

Goal: deliver many secrets to `sst secret load` without writing a dotenv file to disk and without putting values on argv.

```text
  stream_dotenv(variables, write)
           |
           v
  anonymous pipe  (write end in parent)
           |
           |  parent maps read end onto fd 3, pass_fds=(3,)
           v
  child inherits fd 3
           |
           v
  sst secret load /proc/self/fd/3   (or /dev/fd/3)
```

### Components

1. **[`infrastructure/dotenv.py`](../src/secretsync/infrastructure/dotenv.py)** — streams `KEY="quoted"` chunks to a write callback. Rejects bad keys / NUL. Does not keep a combined mega-string for logging.
2. **[`infrastructure/process.py`](../src/secretsync/infrastructure/process.py)** — `AsyncSecureProcessRunner` creates `os.pipe()`, remaps the read end to fd **3** in the parent before spawn (because `preexec_fn` + `close_fds` would close fd 3 if it is not in `pass_fds`), streams dotenv, closes the write end (EOF), awaits with timeout.
3. **[`destinations/sst.py`](../src/secretsync/destinations/sst.py)** — partitions by `(cwd, stage, fallback)`. If `n >= 2` and descriptor probe OK → `secret load <fd-path>`; else per-mutation `secret set` with value on **stdin**.

### Guarantees

- No plaintext tempfile / FIFO for env files
- Minimal child env (no source secrets from parent)
- Stderr summaries redact known secret strings
- Probe uses a non-secret fixture reader, never production SST

### Fallback

When the probe fails (e.g. `bunx` drops fd 3) or `n < 2`, SST uses stdin set. Windows documents set-only.

See security tests: [`tests/security/test_envfile_pipe.py`](../tests/security/test_envfile_pipe.py).

## HTTP client

[`infrastructure/http.py`](../src/secretsync/infrastructure/http.py) wraps httpx with bounded retries (429/502/503/504), no wire body logging, and `redact_headers` / `response_debug_meta` for safe diagnostics. Errors map to `SafeConnectorError` codes without provider body text.

## Errors and reports

`SafeError` / `SafeConnectorError` carry `code`, pre-redacted `message`, optional `hint`, ids, `retryable`, `correlation_id`. JSON reports are versioned (`schemaVersion: 1`) and value-free. Exit codes are stable (see README).

## Test pyramid

| Layer | Location | Focus |
|---|---|---|
| Unit | `tests/unit/` | compose, plan, dotenv, process, presentation, TUI Pilot |
| Contract | `tests/contract/` | protocol + capabilities |
| Integration | `tests/integration/` | mocked GitHub/Vercel; SST doubles |
| Security | `tests/security/` | canaries, env-file pipe, no tempfile |
| Smoke | `tests/smoke/` | opt-in live providers |

Coverage gate: `--cov=secretsync --cov-fail-under=80`.

## Related docs

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [APPENDIX_C_CHECKLIST.md](APPENDIX_C_CHECKLIST.md)
- [SECURITY.md](../SECURITY.md)
