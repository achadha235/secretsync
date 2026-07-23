"""Connector reachability / auth health checks."""

from __future__ import annotations

import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import httpx
from loguru import logger

from secretsync.infrastructure.http import HttpClientFactory
from secretsync.infrastructure.process import (
    AsyncSecureProcessRunner,
    SecureProcessRequest,
    build_minimal_child_env,
)


@dataclass(frozen=True, slots=True)
class HealthCheckResult:
    name: str
    status: str  # ok | fail | skip
    message: str


@dataclass(frozen=True, slots=True)
class HealthReport:
    results: tuple[HealthCheckResult, ...]

    @property
    def exit_code(self) -> int:
        if any(r.status == "fail" for r in self.results):
            return 1
        return 0


async def run_health(
    environ: Mapping[str, str],
    *,
    github_token_env: str = "GITHUB_TOKEN",
    vercel_token_env: str = "VERCEL_TOKEN",
) -> HealthReport:
    results: list[HealthCheckResult] = []
    results.append(await _check_github(environ, github_token_env))
    results.append(await _check_vercel(environ, vercel_token_env))
    results.append(await _check_aws(environ))
    return HealthReport(results=tuple(results))


async def _check_github(environ: Mapping[str, str], token_env: str) -> HealthCheckResult:
    name = "GitHub Actions"
    token = environ.get(token_env)
    if not token:
        msg = f"{token_env} not set, skipping check for GitHub Actions connector"
        logger.info(msg)
        return HealthCheckResult(name=name, status="skip", message=msg)
    logger.debug("Probing GitHub /user")
    try:
        factory = HttpClientFactory()
        async with factory.create(headers={"Authorization": f"Bearer {token}"}) as client:
            response = await client.get("https://api.github.com/user")
        if response.status_code == 200:
            return HealthCheckResult(name=name, status="ok", message="GitHub: OK")
        return HealthCheckResult(
            name=name,
            status="fail",
            message=f"GitHub: FAIL (HTTP {response.status_code})",
        )
    except httpx.HTTPError as exc:
        return HealthCheckResult(
            name=name,
            status="fail",
            message=f"GitHub: FAIL ({type(exc).__name__})",
        )


async def _check_vercel(environ: Mapping[str, str], token_env: str) -> HealthCheckResult:
    name = "Vercel"
    token = environ.get(token_env)
    if not token:
        msg = f"{token_env} not set, skipping check for Vercel connector"
        logger.info(msg)
        return HealthCheckResult(name=name, status="skip", message=msg)
    logger.debug("Probing Vercel /v2/user")
    try:
        factory = HttpClientFactory()
        async with factory.create(headers={"Authorization": f"Bearer {token}"}) as client:
            response = await client.get("https://api.vercel.com/v2/user")
        if response.status_code == 200:
            return HealthCheckResult(name=name, status="ok", message="Vercel: OK")
        return HealthCheckResult(
            name=name,
            status="fail",
            message=f"Vercel: FAIL (HTTP {response.status_code})",
        )
    except httpx.HTTPError as exc:
        return HealthCheckResult(
            name=name,
            status="fail",
            message=f"Vercel: FAIL ({type(exc).__name__})",
        )


async def _check_aws(environ: Mapping[str, str]) -> HealthCheckResult:
    name = "SST / AWS"
    has_profile = bool(environ.get("AWS_PROFILE"))
    has_keys = bool(environ.get("AWS_ACCESS_KEY_ID") and environ.get("AWS_SECRET_ACCESS_KEY"))
    if not has_profile and not has_keys:
        msg = (
            "AWS_PROFILE (or AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY) not set, "
            "skipping check for SST connector"
        )
        logger.info(msg)
        return HealthCheckResult(name=name, status="skip", message=msg)

    aws = shutil.which("aws")
    if not aws:
        return HealthCheckResult(
            name=name,
            status="fail",
            message="SST / AWS: FAIL (aws CLI not found on PATH)",
        )

    args: list[str] = ["sts", "get-caller-identity"]
    profile = environ.get("AWS_PROFILE")
    if profile:
        args.extend(["--profile", profile])

    logger.debug("Running aws sts get-caller-identity")
    runner = AsyncSecureProcessRunner()
    child_env = build_minimal_child_env(environ)
    try:
        result = await runner.execute(
            SecureProcessRequest(
                executable=Path(aws),
                arguments=tuple(args),
                cwd=Path.cwd(),
                environment=child_env,
                timeout_seconds=30.0,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return HealthCheckResult(
            name=name,
            status="fail",
            message=f"SST / AWS: FAIL ({type(exc).__name__})",
        )
    if result.exit_code == 0:
        return HealthCheckResult(name=name, status="ok", message="SST / AWS: OK")
    return HealthCheckResult(
        name=name,
        status="fail",
        message=f"SST / AWS: FAIL (exit {result.exit_code})",
    )


def health_token_envs_from_config(config_path: Path, environ: Mapping[str, str]) -> tuple[str, str]:
    """Best-effort read tokenEnv names from yaml; fall back to defaults."""
    github, vercel = "GITHUB_TOKEN", "VERCEL_TOKEN"
    if not config_path.is_file():
        return github, vercel
    try:
        from secretsync.application.services import create_services

        services = create_services(environ)
        config = services.config_loader.load(config_path)
        for dest in config.destinations.values():
            if dest.connector == "github-actions" and dest.auth and dest.auth.token_env:
                github = dest.auth.token_env
            if dest.connector == "vercel" and dest.auth and dest.auth.token_env:
                vercel = dest.auth.token_env
    except Exception:  # noqa: BLE001 — health still works with defaults
        logger.debug("Could not load config for health token envs; using defaults")
    return github, vercel
