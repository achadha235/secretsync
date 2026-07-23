# SecretSync architecture

This document describes how SecretSync is structured and how secrets move — especially the SST **named-pipe** bulk path.

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

MVP does not detect value drift. `changeDetection: keyed-fingerprint` fails with `UNIMPLEMENTED_CHANGE_DETECTION`.

### Optional prune (plan-time remote reconcile)

With `--prune` on `plan` / `apply` (or the TUI prune checkbox):

1. Group selected deployments into inventory units (destination + normalized scope).
2. Call each connector’s `list_names` (names only).
3. **Deletes** = `remote_names − intended_names` from YAML for that unit.
4. Apply runs **puts first, then deletes** per destination.

There is no local last-applied state file — every prune plan reflects the live remote inventory. Auth/list failures fail the plan; they are not skipped. Connectors without `list_names` + delete support refuse prune with a clear error.

## Connector boundary

Connectors own batching and provider adaptation. The coordinator groups mutations by destination and deployment, then calls `apply` with `PutMutation` values and optional `DeleteMutation`s. Each mutation must receive exactly one result (`applied` / `failed` / `skipped`).

Capabilities are declared in manifests and checked by contract tests.

## Named pipe (SST bulk path)

Goal: deliver many secrets to `sst secret load` without writing a dotenv tempfile to disk and without putting values on argv.

```text
  TemporaryDirectory + os.mkfifo(.env)
           |
           |  writer thread opens FIFO (blocks until reader)
           v
  stream_dotenv(variables, write)
           |
           v
  sst secret load <pipe_path>   ({env_file} substituted at spawn)
```

### Components

1. **[`infrastructure/dotenv.py`](../src/secretsync/infrastructure/dotenv.py)** — streams `KEY="quoted"` chunks to a write callback. Rejects bad keys / NUL. Does not keep a combined mega-string for logging.
2. **[`infrastructure/process.py`](../src/secretsync/infrastructure/process.py)** — `AsyncSecureProcessRunner` creates a mode-`0700` temp dir + `mkfifo`, starts a background writer thread, substitutes `{env_file}` in argv, spawns the child (no fd inheritance), joins the writer, cleans up the temp dir.
3. **[`destinations/sst.py`](../src/secretsync/destinations/sst.py)** — partitions by `(cwd, stage, fallback)`. If `n >= 2` and named-pipe probe OK → `secret load {env_file}`; else per-mutation `secret set` with value on **stdin**.

### Guarantees

- No plaintext dotenv tempfile (FIFO inode only; payload never hits disk)
- Minimal child env (no source secrets from parent)
- Stderr summaries redact known secret strings
- Probe uses a non-secret fixture reader, never production SST

### Fallback

When the probe fails (`mkfifo` unavailable) or `n < 2`, SST uses stdin set. Windows documents set-only.

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
| Security | `tests/security/` | canaries, named-pipe env-file, no plaintext tempfile |
| Smoke | `tests/smoke/` | opt-in live providers |

Coverage gate: `--cov=secretsync --cov-fail-under=80`.
