"""SST secrets destination via secure env-file pipe or stdin set."""

from __future__ import annotations

import sys
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secretsync.destinations.base import (
    ApplyDestinationRequest,
    ApplyDestinationResult,
    BatchCapability,
    DeleteMutation,
    DestinationCapabilities,
    DestinationManifest,
    Issue,
    ListNamesError,
    MutationResult,
    OperationContext,
    PutMutation,
    PutSemantics,
    SafeConnectorError,
)
from secretsync.domain.models import JsonValue
from secretsync.infrastructure.process import (
    ENV_FILE_FD,
    AsyncSecureProcessRunner,
    EnvFileInput,
    ProcessRunnerError,
    SecureProcessRequest,
    build_minimal_child_env,
    preferred_fd_path,
    probe_env_file_descriptor,
    resolve_executable,
)

# Local non-secret reader used only for descriptor capability probes.
_INLINE_READER = "import sys; p=sys.argv[1]; d=open(p,'rb').read(); sys.exit(0 if len(d)>0 else 1)"


def _capabilities() -> DestinationCapabilities:
    return DestinationCapabilities(
        list_names=True,
        read_values=True,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(
            supported=True,
            max_items=None,
            atomic=False,
            transport="env-file-pipe",
        ),
        delete_batch=BatchCapability(supported=True, max_items=1),
        multiple_scopes_per_mutation=False,
        batch_across_scopes=False,
    )


def _working_directory(config: Mapping[str, JsonValue]) -> str | None:
    raw = config.get("workingDirectory")
    return raw if isinstance(raw, str) and raw.strip() else None


def _executable_name(config: Mapping[str, JsonValue]) -> str:
    raw = config.get("executable")
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return "bunx"


def _parse_scope(scope: Mapping[str, JsonValue]) -> tuple[str, bool] | None:
    stage = scope.get("stage")
    if not isinstance(stage, str) or not stage.strip():
        return None
    return stage.strip(), bool(scope.get("fallback", False))


def parse_sst_secret_list_names(stdout: bytes) -> frozenset[str]:
    """Extract secret names from `sst secret list` stdout; discard values immediately."""
    names: set[str] = set()
    for raw_line in stdout.splitlines():
        line = raw_line.decode("utf-8", errors="replace").strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower in {"name", "names", "secret", "secrets"} or set(line) <= {"-", "─", "|", " "}:
            continue
        if "=" in line:
            key = line.split("=", 1)[0].strip()
            if key:
                names.add(key)
            continue
        parts = line.split()
        if parts:
            names.add(parts[0])
    return frozenset(names)


@dataclass
class SstDestination:
    manifest: DestinationManifest
    environ: Mapping[str, str]
    process_runner: AsyncSecureProcessRunner
    _probe_ok: bool | None = None
    _resolved_executable: Path | None = None
    _argv_prefix: tuple[str, ...] = ()

    async def validate(self, config: Mapping[str, JsonValue]) -> list[Issue]:
        issues: list[Issue] = []
        if _working_directory(config) is None:
            issues.append(
                Issue(code="DESTINATION_INVALID", message="sst requires workingDirectory")
            )
        if not _executable_name(config):
            issues.append(
                Issue(code="DESTINATION_INVALID", message="sst executable must be non-empty")
            )
        return issues

    async def list_names(
        self,
        config: Mapping[str, JsonValue],
        scope: Mapping[str, JsonValue],
        context: OperationContext,
    ) -> frozenset[str]:
        wd = _working_directory(config)
        if wd is None:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Invalid sst destination configuration",
                    correlation_id=context.correlation_id,
                )
            )
        parsed = _parse_scope(dict(scope))
        if parsed is None:
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="SST scope.stage is required",
                    correlation_id=context.correlation_id,
                )
            )
        stage, fallback = parsed
        cwd = Path(wd).expanduser()
        if not cwd.is_absolute():
            cwd = (Path.cwd() / cwd).resolve()
        if not cwd.is_dir():
            raise ListNamesError(
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=f"workingDirectory does not exist: {cwd}",
                    correlation_id=context.correlation_id,
                )
            )
        try:
            await self._ensure_command(config, cwd)
        except ProcessRunnerError as exc:
            raise ListNamesError(exc.safe) from exc
        assert self._resolved_executable is not None
        args = [*self._argv_prefix, "secret", "list", "--stage", stage]
        if fallback:
            args.append("--fallback")
        req = SecureProcessRequest(
            executable=self._resolved_executable,
            arguments=tuple(args),
            cwd=cwd,
            environment=build_minimal_child_env(self.environ),
            capture_stdout=True,
        )
        try:
            result = await self.process_runner.execute(req)
        except ProcessRunnerError as exc:
            raise ListNamesError(exc.safe) from exc
        if result.exit_code != 0:
            raise ListNamesError(
                SafeConnectorError(
                    code="PROCESS_FAILED",
                    message="SST secret list failed",
                    correlation_id=context.correlation_id,
                    hint=result.stderr_summary or None,
                )
            )
        names = parse_sst_secret_list_names(result.stdout_bytes)
        del result
        return names

    async def apply(
        self,
        request: ApplyDestinationRequest,
        context: OperationContext,
    ) -> ApplyDestinationResult:
        config = request.destination_config
        wd = _working_directory(config)
        all_ids = [m.mutation_id for m in request.mutations] + [
            d.mutation_id for d in request.deletes
        ]
        if wd is None:
            return _all_failed_ids(
                all_ids,
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message="Invalid sst destination configuration",
                    correlation_id=context.correlation_id,
                ),
            )

        cwd = Path(wd).expanduser()
        if not cwd.is_absolute():
            cwd = (Path.cwd() / cwd).resolve()
        if not cwd.is_dir():
            return _all_failed_ids(
                all_ids,
                SafeConnectorError(
                    code="DESTINATION_INVALID",
                    message=f"workingDirectory does not exist: {cwd}",
                    correlation_id=context.correlation_id,
                ),
            )

        partitions: dict[tuple[str, bool], list[PutMutation]] = defaultdict(list)
        for mutation in request.mutations:
            if not mutation.scopes:
                return _all_failed_ids(
                    all_ids,
                    SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing SST scope on mutation",
                        mutation_id=mutation.mutation_id,
                        correlation_id=context.correlation_id,
                    ),
                )
            parsed = _parse_scope(dict(mutation.scopes[0]))
            if parsed is None:
                return _all_failed_ids(
                    all_ids,
                    SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="SST scope.stage is required",
                        mutation_id=mutation.mutation_id,
                        correlation_id=context.correlation_id,
                    ),
                )
            partitions[parsed].append(mutation)

        delete_partitions: dict[tuple[str, bool], list[DeleteMutation]] = defaultdict(list)
        for deletion in request.deletes:
            if not deletion.scopes:
                return _all_failed_ids(
                    all_ids,
                    SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="Missing SST scope on delete",
                        mutation_id=deletion.mutation_id,
                        correlation_id=context.correlation_id,
                    ),
                )
            parsed = _parse_scope(dict(deletion.scopes[0]))
            if parsed is None:
                return _all_failed_ids(
                    all_ids,
                    SafeConnectorError(
                        code="DESTINATION_INVALID",
                        message="SST scope.stage is required",
                        mutation_id=deletion.mutation_id,
                        correlation_id=context.correlation_id,
                    ),
                )
            delete_partitions[parsed].append(deletion)

        try:
            await self._ensure_command(config, cwd)
        except ProcessRunnerError as exc:
            return _all_failed_ids(all_ids, exc.safe)

        assert self._resolved_executable is not None
        child_env = build_minimal_child_env(self.environ)
        results: dict[str, MutationResult] = {}
        requests_made = 0

        for (stage, fallback), mutations in partitions.items():
            use_bulk = len(mutations) >= 2 and bool(self._probe_ok)
            if use_bulk:
                part_results, n = await self._bulk_load(
                    cwd=cwd,
                    stage=stage,
                    fallback=fallback,
                    mutations=mutations,
                    child_env=child_env,
                    correlation_id=context.correlation_id,
                )
            else:
                part_results, n = await self._individual_sets(
                    cwd=cwd,
                    stage=stage,
                    fallback=fallback,
                    mutations=mutations,
                    child_env=child_env,
                    correlation_id=context.correlation_id,
                )
            requests_made += n
            results.update(part_results)

        for (stage, fallback), deletions in delete_partitions.items():
            part_results, n = await self._individual_removes(
                cwd=cwd,
                stage=stage,
                fallback=fallback,
                deletes=deletions,
                child_env=child_env,
                correlation_id=context.correlation_id,
            )
            requests_made += n
            results.update(part_results)

        ordered = tuple(results[mid] for mid in all_ids)
        return ApplyDestinationResult(results=ordered, requests_made=requests_made)

    async def _ensure_command(self, config: Mapping[str, JsonValue], cwd: Path) -> None:
        if self._resolved_executable is not None:
            return

        name = _executable_name(config)
        exe = resolve_executable(name)
        if exe is None:
            raise ProcessRunnerError(
                SafeConnectorError(
                    code="PROCESS_FAILED",
                    message=f"SST executable '{name}' not found on PATH",
                )
            )

        # OS-level pipe probe (python reader). Independent of bunx/sst.
        os_probe = await probe_env_file_descriptor(
            self.process_runner,
            reader_executable=Path(sys.executable),
            reader_args=("-c", _INLINE_READER),
            cwd=cwd,
            environment=build_minimal_child_env(self.environ),
        )

        if name == "bunx":
            # Prefer direct `sst` when available so fd 3 is not lost through bunx.
            sst = resolve_executable("sst")
            if sst is not None:
                self._resolved_executable = sst
                self._argv_prefix = ()
                self._probe_ok = os_probe
                return
            self._resolved_executable = exe
            self._argv_prefix = ("sst",)
            # Without a direct sst binary, avoid bulk pipe through bunx.
            self._probe_ok = False
            return

        self._resolved_executable = exe
        self._argv_prefix = ()
        self._probe_ok = os_probe

    async def _bulk_load(
        self,
        *,
        cwd: Path,
        stage: str,
        fallback: bool,
        mutations: Sequence[PutMutation],
        child_env: Mapping[str, str],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        assert self._resolved_executable is not None
        fd_path = preferred_fd_path(ENV_FILE_FD)
        args = [*self._argv_prefix, "secret", "load", fd_path, "--stage", stage]
        if fallback:
            args.append("--fallback")
        variables = {m.name: bytes(m.value) for m in mutations}
        req = SecureProcessRequest(
            executable=self._resolved_executable,
            arguments=tuple(args),
            cwd=cwd,
            environment=dict(child_env),
            env_file=EnvFileInput(variables=variables),
        )
        try:
            result = await self.process_runner.execute(req)
        except ProcessRunnerError as exc:
            return (_fanout_failed(mutations, exc.safe, correlation_id), 1)
        if result.exit_code != 0:
            error = SafeConnectorError(
                code="PROCESS_FAILED",
                message="SST secret load failed",
                correlation_id=correlation_id,
                hint=result.stderr_summary or None,
            )
            return (_fanout_failed(mutations, error, correlation_id), 1)
        return (
            {
                m.mutation_id: MutationResult(
                    mutation_id=m.mutation_id,
                    status="applied",
                    effect="upserted",
                )
                for m in mutations
            },
            1,
        )

    async def _individual_sets(
        self,
        *,
        cwd: Path,
        stage: str,
        fallback: bool,
        mutations: Sequence[PutMutation],
        child_env: Mapping[str, str],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        assert self._resolved_executable is not None
        results: dict[str, MutationResult] = {}
        requests = 0
        for mutation in mutations:
            args = [*self._argv_prefix, "secret", "set", mutation.name, "--stage", stage]
            if fallback:
                args.append("--fallback")
            req = SecureProcessRequest(
                executable=self._resolved_executable,
                arguments=tuple(args),
                cwd=cwd,
                environment=dict(child_env),
                stdin_bytes=bytes(mutation.value),
            )
            requests += 1
            try:
                result = await self.process_runner.execute(req)
            except ProcessRunnerError as exc:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code=exc.safe.code,
                        message=exc.safe.message,
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            if result.exit_code != 0:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="PROCESS_FAILED",
                        message="SST secret set failed",
                        mutation_id=mutation.mutation_id,
                        correlation_id=correlation_id,
                        hint=result.stderr_summary or None,
                    ),
                )
            else:
                results[mutation.mutation_id] = MutationResult(
                    mutation_id=mutation.mutation_id,
                    status="applied",
                    effect="upserted",
                )
        return results, requests

    async def _individual_removes(
        self,
        *,
        cwd: Path,
        stage: str,
        fallback: bool,
        deletes: Sequence[DeleteMutation],
        child_env: Mapping[str, str],
        correlation_id: str,
    ) -> tuple[dict[str, MutationResult], int]:
        assert self._resolved_executable is not None
        results: dict[str, MutationResult] = {}
        requests = 0
        for deletion in deletes:
            args = [*self._argv_prefix, "secret", "remove", deletion.name, "--stage", stage]
            if fallback:
                args.append("--fallback")
            req = SecureProcessRequest(
                executable=self._resolved_executable,
                arguments=tuple(args),
                cwd=cwd,
                environment=dict(child_env),
            )
            requests += 1
            try:
                result = await self.process_runner.execute(req)
            except ProcessRunnerError as exc:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code=exc.safe.code,
                        message=exc.safe.message,
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                    ),
                )
                continue
            if result.exit_code != 0:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="failed",
                    error=SafeConnectorError(
                        code="PROCESS_FAILED",
                        message="SST secret remove failed",
                        mutation_id=deletion.mutation_id,
                        correlation_id=correlation_id,
                        hint=result.stderr_summary or None,
                    ),
                )
            else:
                results[deletion.mutation_id] = MutationResult(
                    mutation_id=deletion.mutation_id,
                    status="applied",
                    effect="deleted",
                )
        return results, requests


def _fanout_failed(
    mutations: Sequence[PutMutation],
    error: SafeConnectorError,
    correlation_id: str,
) -> dict[str, MutationResult]:
    return {
        m.mutation_id: MutationResult(
            mutation_id=m.mutation_id,
            status="failed",
            error=SafeConnectorError(
                code=error.code,
                message=error.message,
                mutation_id=m.mutation_id,
                correlation_id=correlation_id,
                hint=error.hint,
                retryable=error.retryable,
            ),
        )
        for m in mutations
    }


def _all_failed_ids(
    mutation_ids: Sequence[str], error: SafeConnectorError
) -> ApplyDestinationResult:
    return ApplyDestinationResult(
        results=tuple(
            MutationResult(mutation_id=mid, status="failed", error=error) for mid in mutation_ids
        ),
        requests_made=0,
    )


@dataclass(frozen=True, slots=True)
class SstFactory:
    manifest: DestinationManifest = field(
        default_factory=lambda: DestinationManifest(
            id="sst",
            version="0.1.0+env-file-pipe",
            capabilities=_capabilities(),
        )
    )

    def create(self, services: Any) -> SstDestination:
        return SstDestination(
            manifest=self.manifest,
            environ=services.environ,
            process_runner=services.process_runner,
        )
