"""Opt-in live provider smoke tests. Skipped unless SECRETSYNC_SMOKE=1."""

from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.smoke


def _smoke_enabled() -> bool:
    return os.environ.get("SECRETSYNC_SMOKE") == "1"


@pytest.mark.asyncio
async def test_github_smoke_put() -> None:
    if not _smoke_enabled():
        pytest.skip("Set SECRETSYNC_SMOKE=1 with GITHUB_TOKEN and SECRETSYNC_SMOKE_GITHUB_REPO")
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("SECRETSYNC_SMOKE_GITHUB_REPO")
    if not token or not repo:
        pytest.skip("GITHUB_TOKEN and SECRETSYNC_SMOKE_GITHUB_REPO required")

    from secretsync.application.services import create_services
    from secretsync.destinations.base import ApplyDestinationRequest, OperationContext, PutMutation
    from secretsync.destinations.github_actions import GitHubActionsFactory

    services = create_services({"GITHUB_TOKEN": token})
    dest = GitHubActionsFactory().create(services)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="smoke",
            destination_config={
                "connector": "github-actions",
                "repository": repo,
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[
                PutMutation(
                    mutation_id="smoke:SECRETSYNC_SMOKE",
                    name="SECRETSYNC_SMOKE",
                    value=bytearray(b"smoke-ok"),
                    scopes=({"kind": "repository"},),
                )
            ],
        ),
        OperationContext(correlation_id="smoke-gh"),
    )
    assert result.results[0].status == "applied"


@pytest.mark.asyncio
async def test_vercel_smoke_upsert() -> None:
    if not _smoke_enabled():
        pytest.skip("Set SECRETSYNC_SMOKE=1 with VERCEL_TOKEN and SECRETSYNC_SMOKE_VERCEL_PROJECT")
    token = os.environ.get("VERCEL_TOKEN")
    project = os.environ.get("SECRETSYNC_SMOKE_VERCEL_PROJECT")
    team = os.environ.get("SECRETSYNC_SMOKE_VERCEL_TEAM_ID")
    if not token or not project:
        pytest.skip("VERCEL_TOKEN and SECRETSYNC_SMOKE_VERCEL_PROJECT required")

    from secretsync.application.services import create_services
    from secretsync.destinations.base import ApplyDestinationRequest, OperationContext, PutMutation
    from secretsync.destinations.vercel import VercelFactory
    from secretsync.domain.models import ValueKind

    services = create_services({"VERCEL_TOKEN": token})
    dest = VercelFactory().create(services)
    config: dict[str, object] = {
        "connector": "vercel",
        "project": project,
        "auth": {"tokenEnv": "VERCEL_TOKEN"},
    }
    if team:
        config["teamId"] = team
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="smoke",
            destination_config=config,  # type: ignore[arg-type]
            mutations=[
                PutMutation(
                    mutation_id="smoke:SECRETSYNC_SMOKE",
                    name="SECRETSYNC_SMOKE",
                    value=bytearray(b"smoke-ok"),
                    scopes=({"targets": ["preview"]},),
                    kind=ValueKind.SECRET,
                )
            ],
        ),
        OperationContext(correlation_id="smoke-vc"),
    )
    assert result.results[0].status == "applied"


@pytest.mark.asyncio
async def test_sst_smoke_set() -> None:
    if not _smoke_enabled():
        pytest.skip("Set SECRETSYNC_SMOKE=1 with SECRETSYNC_SMOKE_SST_DIR")
    workdir = os.environ.get("SECRETSYNC_SMOKE_SST_DIR")
    stage = os.environ.get("SECRETSYNC_SMOKE_SST_STAGE", "development")
    if not workdir:
        pytest.skip("SECRETSYNC_SMOKE_SST_DIR required")

    from secretsync.application.services import create_services
    from secretsync.destinations.base import ApplyDestinationRequest, OperationContext, PutMutation
    from secretsync.destinations.sst import SstFactory

    services = create_services(dict(os.environ))
    dest = SstFactory().create(services)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="smoke",
            destination_config={
                "connector": "sst",
                "workingDirectory": workdir,
                "executable": os.environ.get("SECRETSYNC_SMOKE_SST_EXECUTABLE", "sst"),
            },
            mutations=[
                PutMutation(
                    mutation_id="smoke:SECRETSYNC_SMOKE",
                    name="SECRETSYNC_SMOKE",
                    value=bytearray(b"smoke-ok"),
                    scopes=({"stage": stage, "fallback": False},),
                )
            ],
        ),
        OperationContext(correlation_id="smoke-sst"),
    )
    assert result.results[0].status == "applied"
