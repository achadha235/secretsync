from __future__ import annotations

import httpx
import pytest
import respx

from secretsync.application.services import create_services
from secretsync.destinations.base import ApplyDestinationRequest, OperationContext, PutMutation
from secretsync.destinations.vercel import VercelFactory
from secretsync.domain.models import ValueKind


def _services() -> object:
    return create_services({"VERCEL_TOKEN": "vercel_test_token"})


def _mutation(
    name: str,
    *,
    targets: list[str] | None = None,
    kind: ValueKind = ValueKind.SECRET,
    git_branch: str | None = None,
    value: bytes = b"SECRET_CANARY_vc",
    extra_scope: dict[str, object] | None = None,
) -> PutMutation:
    scope: dict[str, object] = {"targets": targets or ["production"]}
    if git_branch is not None:
        scope["gitBranch"] = git_branch
    if extra_scope:
        scope.update(extra_scope)
    return PutMutation(
        mutation_id=f"dep:{name}",
        name=name,
        value=bytearray(value),
        scopes=(scope,),  # type: ignore[arg-type]
        kind=kind,
    )


@pytest.mark.asyncio
async def test_validate_requires_project_and_auth() -> None:
    dest = VercelFactory().create(_services())
    issues = await dest.validate({"connector": "vercel"})
    assert any("project" in i.message for i in issues)


@pytest.mark.asyncio
async def test_secret_rejects_development_target() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation("A", targets=["development"], kind=ValueKind.SECRET)],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "sensitive" in result.results[0].error.message.lower()


@pytest.mark.asyncio
async def test_scope_sensitive_rejected() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation("A", extra_scope={"sensitive": True})],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "scope.sensitive" in result.results[0].error.message


@pytest.mark.asyncio
@respx.mock
async def test_bulk_upsert_secret_type_sensitive() -> None:
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
                _mutation("DATABASE_URL", kind=ValueKind.SECRET),
                _mutation("API_TOKEN", kind=ValueKind.SECRET),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "applied" and r.effect == "upserted" for r in result.results)
    assert route.calls[0].request.url.params["upsert"] == "true"
    assert route.calls[0].request.url.params["teamId"] == "team_abc"
    body = route.calls[0].request.read()
    assert b'"type":"sensitive"' in body or b'"type": "sensitive"' in body
    assert b"SECRET_CANARY_vc" in body
    assert b"SECRET_CANARY_vc" not in repr(result).encode()


@pytest.mark.asyncio
@respx.mock
async def test_bulk_upsert_variable_type_encrypted() -> None:
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
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[
                _mutation("PUBLIC_APP_URL", kind=ValueKind.VARIABLE, value=b"https://app.example"),
                _mutation("LOG_LEVEL", kind=ValueKind.VARIABLE, value=b"info"),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "applied" for r in result.results)
    body = route.calls[0].request.read()
    assert b'"type":"encrypted"' in body or b'"type": "encrypted"' in body
    assert b"sensitive" not in body or body.count(b"sensitive") == 0


@pytest.mark.asyncio
@respx.mock
async def test_mixed_secret_and_variable_types() -> None:
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
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[
                _mutation("API_KEY", kind=ValueKind.SECRET),
                _mutation("LOG_LEVEL", kind=ValueKind.VARIABLE, value=b"debug"),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "applied" for r in result.results)
    import json

    payload = json.loads(route.calls[0].request.read())
    by_key = {item["key"]: item["type"] for item in payload}
    assert by_key["API_KEY"] == "sensitive"
    assert by_key["LOG_LEVEL"] == "encrypted"


@pytest.mark.asyncio
@respx.mock
async def test_chunking_requests_made() -> None:
    from secretsync.destinations.base import (
        BatchCapability,
        DestinationCapabilities,
        DestinationManifest,
        PutSemantics,
    )

    route = respx.post("https://api.vercel.com/v10/projects/web/env").mock(
        return_value=httpx.Response(200, json={})
    )
    dest = VercelFactory().create(_services())
    dest.manifest = DestinationManifest(
        id="vercel",
        version="test",
        capabilities=DestinationCapabilities(
            list_names=True,
            read_values=True,
            put_semantics=PutSemantics.UPSERT,
            put_batch=BatchCapability(supported=True, max_items=2, transport="api"),
            delete_batch=BatchCapability(supported=True),
            multiple_scopes_per_mutation=True,
            batch_across_scopes=True,
        ),
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


@pytest.mark.asyncio
@respx.mock
async def test_list_names_filters_by_kind_type() -> None:
    respx.get("https://api.vercel.com/v9/projects/web/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "envs": [
                    {"key": "SECRET_A", "id": "1", "target": ["production"], "type": "sensitive"},
                    {"key": "VAR_B", "id": "2", "target": ["production"], "type": "encrypted"},
                    {"key": "OTHER", "id": "3", "target": ["preview"], "type": "sensitive"},
                ]
            },
        )
    )
    dest = VercelFactory().create(_services())
    secrets = await dest.list_names(
        {"project": "web", "auth": {"tokenEnv": "VERCEL_TOKEN"}},
        {"targets": ["production"]},
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    variables = await dest.list_names(
        {"project": "web", "auth": {"tokenEnv": "VERCEL_TOKEN"}},
        {"targets": ["production"]},
        OperationContext(correlation_id="c1"),
        kind=ValueKind.VARIABLE,
    )
    assert secrets == frozenset({"SECRET_A"})
    assert variables == frozenset({"VAR_B"})


@pytest.mark.asyncio
@respx.mock
async def test_git_branch_validation() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "vercel",
                "project": "web",
                "auth": {"tokenEnv": "VERCEL_TOKEN"},
            },
            mutations=[_mutation("A", targets=["production"], git_branch="feat")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "gitBranch" in result.results[0].error.message


@pytest.mark.asyncio
@respx.mock
async def test_variable_allows_development_target() -> None:
    route = respx.post("https://api.vercel.com/v10/projects/web/env").mock(
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
            mutations=[
                _mutation("LOG_LEVEL", targets=["development"], kind=ValueKind.VARIABLE, value=b"x")
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_batch_failure_marks_all() -> None:
    respx.post("https://api.vercel.com/v10/projects/web/env").mock(return_value=httpx.Response(500))
    dest = VercelFactory().create(_services())
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
            json={
                "envs": [
                    {
                        "id": "env_1",
                        "key": "DATABASE_URL",
                        "type": "sensitive",
                        "target": ["production"],
                    }
                ]
            },
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


@pytest.mark.asyncio
@respx.mock
async def test_list_names_filters_by_targets() -> None:
    respx.get("https://api.vercel.com/v9/projects/web/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "envs": [
                    {"id": "1", "key": "KEEP", "target": ["production"], "type": "encrypted"},
                    {"id": "2", "key": "OTHER", "target": ["preview"], "type": "encrypted"},
                    {
                        "id": "3",
                        "key": "BOTH",
                        "target": ["production", "preview"],
                        "type": "encrypted",
                    },
                ]
            },
        )
    )
    dest = VercelFactory().create(_services())
    names = await dest.list_names(
        {
            "connector": "vercel",
            "project": "web",
            "auth": {"tokenEnv": "VERCEL_TOKEN"},
        },
        {"targets": ["production"]},
        OperationContext(correlation_id="c1"),
        kind=ValueKind.VARIABLE,
    )
    assert names == frozenset({"KEEP", "BOTH"})


@pytest.mark.asyncio
@respx.mock
async def test_delete_env_by_id() -> None:
    from secretsync.destinations.base import DeleteMutation

    respx.get("https://api.vercel.com/v9/projects/web/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "envs": [
                    {
                        "id": "env_orphan",
                        "key": "ORPHAN",
                        "target": ["production"],
                        "type": "encrypted",
                    },
                ]
            },
        )
    )
    delete = respx.delete("https://api.vercel.com/v9/projects/web/env/env_orphan").mock(
        return_value=httpx.Response(204)
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
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:ORPHAN",
                    name="ORPHAN",
                    scopes=({"targets": ["production"]},),
                    kind=ValueKind.VARIABLE,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert delete.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"
