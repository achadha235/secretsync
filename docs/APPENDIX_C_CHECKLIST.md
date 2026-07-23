# Appendix C — Engineering review checklist

MVP acceptance checklist. Each item points to tests and/or docs.

## Configuration

| Item | Status | Evidence |
|---|---|---|
| Unknown keys rejected | Done | Pydantic config models; unit validate fixtures |
| Cycles detected | Done | `tests/fixtures/cycle.yaml` + compose/validate tests |
| Publication explicit | Done | Deployment `secrets:` mapping required |
| Duplicate final targets rejected | Done | `duplicate_target` fixture |
| Source values resolved after structural validation | Done | Apply coordinator resolve-after-plan |

## Security

| Item | Status | Evidence |
|---|---|---|
| No secret argv | Done | SST stdin/fd path; `tests/security/test_envfile_pipe.py` |
| No temporary plaintext file | Done | `test_sst_no_tempfile.py`, env-file pipe suite |
| No request-body logging | Done | HTTP client has no body event hooks |
| Minimal child environment | Done | `build_minimal_child_env`; spy test |
| Canary scan passes | Done | `tests/security/` + CI `-m security` |
| SST descriptor inheritance tested | Done | process runner + env-file pipe tests (Linux/macOS CI) |

## Connectors

| Item | Status | Evidence |
|---|---|---|
| One result per mutation | Done | Contract + apply correlation helpers |
| Capabilities accurate | Done | `tests/contract/test_provider_capabilities.py` |
| Rate limits handled | Done | HTTP retry on 429; SafeError `DESTINATION_RATE_LIMITED` |
| Partial failures preserved | Done | Apply summary exit 5/6; fake fail fixtures |
| Provider API assumptions contract-tested | Done | Integration mocks for GitHub/Vercel; SST doubles |

## UX

| Item | Status | Evidence |
|---|---|---|
| Plan says always write | Done | Human/JSON plan renderers; README |
| TUI never renders values | Done | Pilot canary scans; Results export value-free |
| JSON versioned | Done | `schemaVersion: 1` in presentation JSON |
| Exit codes stable | Done | `domain/errors.py` + CLI tests |
| Cancellation wording acknowledges partial writes | Done | TUI ExecutionScreen cancel copy; apply interrupted report |

## Docs / packaging (M6)

| Item | Status | Evidence |
|---|---|---|
| Quickstart works with examples | Done | README + `examples/.env.example` |
| Release notes warn always-write + redeploy | Done | CHANGELOG + release workflow body |
| LICENSE / checksums / release workflow | Done | LICENSE, release.yml SHA256SUMS |
| Threat-model review | Done | `docs/THREAT_MODEL.md` |
