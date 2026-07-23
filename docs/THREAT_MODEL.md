# Threat model (MVP)

Aligned with the SecretSync MVP technical specification §2.3. Reviewed for M6 acceptance.

## Assets

- Resolved secret values in process memory during apply
- Destination credentials (`GITHUB_TOKEN`, `VERCEL_TOKEN`, `AWS_*`)
- Provider-side secret stores (GitHub Actions, Vercel env, SST secrets)

## Actors / threats and mitigations

| Threat | Mitigation in SecretSync | Residual risk |
|---|---|---|
| Git commit of secrets | Config stores env **names** only; plans/JSON value-free | User may still put plaintext in `.env` and commit it — `.gitignore` blocks `.env` |
| Argv / process listing | SST values via stdin or fd pipe; never value argv | Other tools on the host may still dump memory |
| Logs / tracebacks | Redaction helpers; SafeError messages; no HTTP body logging | Misconfigured log aggregation outside process |
| Temp-file recovery | No plaintext dotenv tempfile; anonymous pipe fd 3 | Kernel pipe buffers still in memory while open |
| Malicious / buggy connector | Protocol + contract tests; scrub `bytearray` after apply | A compromised connector binary could exfiltrate |
| Partial provider failure | Per-mutation status; non-zero exit; no rollback claim; TUI cancel wording | Completed writes remain at the provider |

## SST pipe specifics

- Parent remaps pipe read end to fd 3 before spawn; child opens `/proc/self/fd/3` or `/dev/fd/3`
- Streaming encoder avoids retaining a single logged mega-string
- Probe uses a non-secret fixture; production SST is not used for probing
- On EPIPE/timeout, errors are safe-coded; canaries must not appear in messages

## Residual risks (accepted for MVP)

- Host paging / swap / core dumps may expose process memory
- Successful Vercel/SST writes may require a separate deploy to take effect
- Always-write may overwrite intentional manual provider edits

## Review checklist

- [x] Threats above mapped to code/tests (M6)
- [x] Security canary suite in default CI (Linux + macOS)
- [x] Appendix C items tracked in [APPENDIX_C_CHECKLIST.md](APPENDIX_C_CHECKLIST.md)
