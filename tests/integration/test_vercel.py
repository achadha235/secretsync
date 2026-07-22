from __future__ import annotations

import httpx
import pytest
import respx

from secretsync.application.services import create_services
from secretsync.destinations.base import ApplyDestinationRequest, OperationContext, PutMutation
from secretsync.destinations.vercel import VercelFactory


def _services() -> object:
    return create_services({"VERCEL_TOKEN": "vercel_test_token"})


def _mutation(
    name: str,
    *,
    targets: list[str] | None = None,
    sensitive: bool = False,
    git_branch: str | None = None,
    value: bytes = b"SECRET_CANARY_vc",
) -> PutMutation:
    scope: dict[str, object] = {"targets": targets or ["production"], "sensitive": sensitive}
    if git_branch is not None:
        scope["gitBranch"] = git_branch
    return PutMutation(
        mutation_id=f"dep:{name}",
        name=name,
        value=bytearray(value),
        scopes=(scope,),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_validate_requires_project_and_auth() -> None:
    dest = VercelFactory().create(_services())
    issues = await dest.validate({"connector": "vercel"})
    assert any("project" in i.message for i in issues)


@pytest.mark.asyncio
async def test_sensitive_rejects_development() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation("A", targets=["development"], sensitive=True)],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "sensitive" in result.results[0].error.message.lower()


@pytest.mark.asyncio
@respx.mock
async def test_bulk_upsert_payload_and_team_id() -> None:
    route = respx.post("https://api.vercel.com/v10/projects/web/env").mock(
        return_value=httpx.Response(200, json={"created": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "teamId": "team_abc",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[
                _mutation("DATABASE_URL", sensitive=True),
                _mutation("API_TOKEN", sensitive=True),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "applied" and r.effect == "upserted" for r in result.results)
    assert route.calls[0].request.url.params["upsert"] == "true"
    assert route.calls[0].request.url.params["teamId"] == "team_abc"
    body = route.calls[0].request.read()
    assert b"SECRET_CANARY_vc" in body  # request body to provider is expected
    assert b"SECRET_CANARY_vc" not in repr(result).encode()


@pytest.mark.asyncio
@respx.mock
async def test_chunking_requests_made() -> None:
    from secretsync.destinations.base import (
        BatchCapability,
        DestinationCapabilities,
        DestinationManifest,
        PutSemantics,
    )
    from secretsync.destinations.vercel import VercelDestination

    caps = DestinationCapabilities(
        list_names=True,
        read_values=True,
        put_semantics=PutSemantics.UPSERT,
        put_batch=BatchCapability(supported=True, max_items=2, atomic=False, transport="api"),
        delete_batch=BatchCapability(supported=True),
        multiple_scopes_per_mutation=True,
        batch_across_scopes=True,
    )
    dest = VercelDestination(
        manifest=DestinationManifest(id="vercel", version="test", capabilities=caps),
        environ={"VERCEL_TOKEN": "t"},
        http_client_factory=create_services({}).http_client_factory,
    )
    route = respx.post("https://api.vercel.com/v10/projects/web/env").mock(
        return_value=httpx.Response(201, json={})
    )
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation(f"K{i}") for i in range(5)],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 3
    assert route.call_count == 3
    assert len(result.results) == 5


@pytest.mark.asyncio
@respx.mock
async def test_batch_failure_marks_all() -> None:
    respx.post("https://api.vercel.com/v10/projects/web/env").mock(return_value=httpx.Response(500))
    dest = VercelFactory().create(_services())
    # Exhaust retries quickly by mocking many 500s — request_with_retries will raise
    # Actually 500 is not in retry set; only 502/503/504. 500 returns immediately.
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation("A"), _mutation("B")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "failed" for r in result.results)
    assert result.results[0].error is not None
    assert result.results[0].error.correlation_id == "c1"


@pytest.mark.asyncio
@respx.mock
async def test_conflict_edit_fallback() -> None:
    respx.post("https://api.vercel.com/v10/projects/web/env").mock(
        return_value=httpx.Response(409, json={"error": "exists"})
    )
    respx.get("https://api.vercel.com/v9/projects/web/env").mock(
        return_value=httpx.Response(
            200,
            json={"envs": [{"id": "env_1", "key": "DATABASE_URL"}]},
        )
    )
    patch = respx.patch("https://api.vercel.com/v9/projects/web/env/env_1").mock(
        return_value=httpx.Response(200, json={})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation("DATABASE_URL")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert patch.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "updated"
    assert result.requests_made >= 2
