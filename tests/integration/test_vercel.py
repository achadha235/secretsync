from __future__ import annotations

import json

import httpx
import pytest
import respx

from secretsync.application.services import create_services
from secretsync.destinations.base import (
    ApplyDestinationRequest,
    DeleteMutation,
    OperationContext,
    PutMutation,
)
from secretsync.destinations.vercel import VercelFactory
from secretsync.domain.models import ValueKind


def _services() -> object:
    return create_services({"VERCEL_TOKEN": "vercel_test_token"})


def _dest_config(**extra: object) -> dict[str, object]:
    config: dict[str, object] = {
        "connector": "vercel",
        "teamId": "team_abc",
        "auth": {"tokenEnv": "VERCEL_TOKEN"},
    }
    config.update(extra)
    return config


def _mutation(
    name: str,
    *,
    targets: list[str] | None = None,
    kind: ValueKind = ValueKind.SECRET,
    scope_kind: str = "environment",
    git_branch: str | None = None,
    projects: list[str] | None = None,
    value: bytes = b"SECRET_CANARY_vc",
    extra_scope: dict[str, object] | None = None,
) -> PutMutation:
    scope: dict[str, object] = {
        "kind": scope_kind,
        "targets": targets or ["production"],
    }
    if git_branch is not None:
        scope["gitBranch"] = git_branch
    if projects is not None:
        scope["projects"] = projects
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
async def test_validate_requires_team_id_and_auth() -> None:
    dest = VercelFactory().create(_services())
    issues = await dest.validate({"connector": "vercel"})
    assert any("teamId" in i.message for i in issues)
    assert any(i.code == "AUTH_MISSING" for i in issues)


@pytest.mark.asyncio
async def test_validate_project_optional() -> None:
    dest = VercelFactory().create(_services())
    issues = await dest.validate(
        {
            "connector": "vercel",
            "teamId": "team_abc",
            "auth": {"tokenEnv": "VERCEL_TOKEN"},
        }
    )
    assert issues == []


@pytest.mark.asyncio
async def test_secret_rejects_development_target() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
            mutations=[_mutation("A", extra_scope={"sensitive": True})],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "scope.sensitive" in result.results[0].error.message


@pytest.mark.asyncio
async def test_environment_requires_project() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[_mutation("A")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "project" in result.results[0].error.message


@pytest.mark.asyncio
async def test_environment_rejects_projects() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
            mutations=[_mutation("A", projects=["prj_a"])],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "projects" in result.results[0].error.message


@pytest.mark.asyncio
async def test_shared_rejects_git_branch() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[
                _mutation(
                    "A",
                    scope_kind="shared-environment",
                    git_branch="feat",
                    targets=["preview"],
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "gitBranch" in result.results[0].error.message


@pytest.mark.asyncio
async def test_missing_scope_kind_rejected() -> None:
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
            mutations=[
                PutMutation(
                    mutation_id="dep:A",
                    name="A",
                    value=bytearray(b"x"),
                    scopes=({"targets": ["production"]},),
                    kind=ValueKind.SECRET,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "scope.kind" in result.results[0].error.message


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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
            mutations=[
                _mutation("API_KEY", kind=ValueKind.SECRET),
                _mutation("LOG_LEVEL", kind=ValueKind.VARIABLE, value=b"debug"),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 1
    assert all(r.status == "applied" for r in result.results)
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
    scope = {"kind": "environment", "targets": ["production"]}
    secrets = await dest.list_names(
        _dest_config(project="web"),  # type: ignore[arg-type]
        scope,  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    variables = await dest.list_names(
        _dest_config(project="web"),  # type: ignore[arg-type]
        scope,  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
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
    """Exact target-set match: multi-target remotes are not owned by single-target scopes."""
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
        _dest_config(project="web"),  # type: ignore[arg-type]
        {"kind": "environment", "targets": ["production"]},  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.VARIABLE,
    )
    assert names == frozenset({"KEEP"})


@pytest.mark.asyncio
@respx.mock
async def test_shared_list_exact_targets_partition() -> None:
    """Three-way target partition: common must not list production- or preview-only rows."""
    respx.get("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "1",
                        "key": "SECRET_THREE_ORG",
                        "type": "sensitive",
                        "target": ["production"],
                        "projectId": [],
                    },
                    {
                        "id": "2",
                        "key": "SECRET_THREE_ORG",
                        "type": "sensitive",
                        "target": ["preview"],
                        "projectId": [],
                    },
                    {
                        "id": "3",
                        "key": "SECRET_TWO",
                        "type": "sensitive",
                        "target": ["production", "preview"],
                        "projectId": [],
                    },
                    {
                        "id": "4",
                        "key": "LOG_LEVEL",
                        "type": "encrypted",
                        "target": ["preview"],
                        "projectId": [],
                    },
                    {
                        "id": "5",
                        "key": "ORG_NAME",
                        "type": "encrypted",
                        "target": ["production", "preview"],
                        "projectId": [],
                    },
                ],
                "pagination": {"count": 5, "next": None, "prev": None},
            },
        )
    )
    dest = VercelFactory().create(_services())
    common_secrets = await dest.list_names(
        _dest_config(),  # type: ignore[arg-type]
        {"kind": "shared-environment", "targets": ["production", "preview"]},  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    preview_secrets = await dest.list_names(
        _dest_config(),  # type: ignore[arg-type]
        {"kind": "shared-environment", "targets": ["preview"]},  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    preview_vars = await dest.list_names(
        _dest_config(),  # type: ignore[arg-type]
        {"kind": "shared-environment", "targets": ["preview"]},  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.VARIABLE,
    )
    assert common_secrets == frozenset({"SECRET_TWO"})
    assert preview_secrets == frozenset({"SECRET_THREE_ORG"})
    assert preview_vars == frozenset({"LOG_LEVEL"})


@pytest.mark.asyncio
@respx.mock
async def test_shared_upsert_exact_targets_creates_when_overlap_only() -> None:
    """Preview-only put must create, not patch a production-only row with the same key."""
    respx.get("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "env_prod",
                        "key": "SECRET_THREE_ORG",
                        "type": "sensitive",
                        "target": ["production"],
                        "projectId": [],
                    }
                ],
                "pagination": {"count": 1, "next": None, "prev": None},
            },
        )
    )
    create = respx.post("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(201, json={"created": [], "failed": []})
    )
    patch = respx.patch("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(200, json={"updated": [], "failed": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="preview",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[
                _mutation(
                    "SECRET_THREE_ORG",
                    scope_kind="shared-environment",
                    targets=["preview"],
                    value=b"staging-value",
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "upserted"
    assert create.called
    assert not patch.called
    body = json.loads(create.calls[0].request.read())
    assert body["target"] == ["preview"]
    assert body["evs"][0]["key"] == "SECRET_THREE_ORG"


@pytest.mark.asyncio
@respx.mock
async def test_delete_env_by_id() -> None:
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
            destination_config=_dest_config(project="web"),  # type: ignore[arg-type]
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:ORPHAN",
                    name="ORPHAN",
                    scopes=({"kind": "environment", "targets": ["production"]},),
                    kind=ValueKind.VARIABLE,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert delete.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"


def _empty_shared_list() -> httpx.Response:
    return httpx.Response(
        200,
        json={"data": [], "pagination": {"count": 0, "next": None, "prev": None}},
    )


@pytest.mark.asyncio
@respx.mock
async def test_shared_create() -> None:
    respx.get("https://api.vercel.com/v1/env").mock(return_value=_empty_shared_list())
    create = respx.post("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(201, json={"created": [], "failed": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[
                _mutation(
                    "SHARED_SECRET",
                    scope_kind="shared-environment",
                    projects=["prj_a", "prj_b"],
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "upserted"
    assert create.called
    assert create.calls[0].request.url.params["teamId"] == "team_abc"
    body = json.loads(create.calls[0].request.read())
    assert body["type"] == "sensitive"
    assert body["target"] == ["production"]
    assert body["projectId"] == ["prj_a", "prj_b"]
    assert body["evs"][0]["key"] == "SHARED_SECRET"


@pytest.mark.asyncio
@respx.mock
async def test_shared_create_omits_empty_projects() -> None:
    respx.get("https://api.vercel.com/v1/env").mock(return_value=_empty_shared_list())
    create = respx.post("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(201, json={"created": [], "failed": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[_mutation("UNLINKED", scope_kind="shared-environment")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    body = json.loads(create.calls[0].request.read())
    assert "projectId" not in body


@pytest.mark.asyncio
@respx.mock
async def test_shared_patch_existing() -> None:
    respx.get("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "env_shared_1",
                        "key": "SHARED_SECRET",
                        "type": "sensitive",
                        "target": ["production"],
                        "projectId": ["prj_a", "prj_b"],
                    }
                ],
                "pagination": {"count": 1, "next": None, "prev": None},
            },
        )
    )
    patch = respx.patch("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(200, json={"updated": [], "failed": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[
                _mutation(
                    "SHARED_SECRET",
                    scope_kind="shared-environment",
                    projects=["prj_a", "prj_b"],
                    value=b"rotated",
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "updated"
    assert patch.called
    body = json.loads(patch.calls[0].request.read())
    assert "env_shared_1" in body["updates"]
    assert body["updates"]["env_shared_1"]["value"] == "rotated"
    assert body["updates"]["env_shared_1"]["projectId"] == ["prj_a", "prj_b"]


@pytest.mark.asyncio
@respx.mock
async def test_shared_patch_omits_empty_projects() -> None:
    respx.get("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "env_unlinked",
                        "key": "SECRET_TWO",
                        "type": "sensitive",
                        "target": ["production", "preview"],
                        "projectId": [],
                    }
                ],
                "pagination": {"count": 1, "next": None, "prev": None},
            },
        )
    )
    patch = respx.patch("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(200, json={"updated": [], "failed": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="common",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[
                _mutation(
                    "SECRET_TWO",
                    scope_kind="shared-environment",
                    targets=["production", "preview"],
                    value=b"rotated",
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "updated"
    assert patch.called
    body = json.loads(patch.calls[0].request.read())
    assert "env_unlinked" in body["updates"]
    assert "projectId" not in body["updates"]["env_unlinked"]


@pytest.mark.asyncio
@respx.mock
async def test_shared_list_exact_projects_match() -> None:
    respx.get("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "1",
                        "key": "LINKED",
                        "type": "sensitive",
                        "target": ["production"],
                        "projectId": ["prj_a", "prj_b"],
                    },
                    {
                        "id": "2",
                        "key": "OTHER_LINK",
                        "type": "sensitive",
                        "target": ["production"],
                        "projectId": ["prj_a"],
                    },
                    {
                        "id": "3",
                        "key": "UNLINKED",
                        "type": "sensitive",
                        "target": ["production"],
                        "projectId": [],
                    },
                ],
                "pagination": {"count": 3, "next": None, "prev": None},
            },
        )
    )
    dest = VercelFactory().create(_services())
    linked = await dest.list_names(
        _dest_config(),  # type: ignore[arg-type]
        {
            "kind": "shared-environment",
            "targets": ["production"],
            "projects": ["prj_a", "prj_b"],
        },  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    unlinked = await dest.list_names(
        _dest_config(),  # type: ignore[arg-type]
        {"kind": "shared-environment", "targets": ["production"]},  # type: ignore[arg-type]
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    assert linked == frozenset({"LINKED"})
    assert unlinked == frozenset({"UNLINKED"})


@pytest.mark.asyncio
@respx.mock
async def test_shared_delete() -> None:
    respx.get("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "id": "env_orphan",
                        "key": "ORPHAN",
                        "type": "encrypted",
                        "target": ["production"],
                        "projectId": [],
                    }
                ],
                "pagination": {"count": 1, "next": None, "prev": None},
            },
        )
    )
    delete = respx.delete("https://api.vercel.com/v1/env").mock(
        return_value=httpx.Response(200, json={"deleted": ["env_orphan"], "failed": []})
    )
    dest = VercelFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config=_dest_config(),  # type: ignore[arg-type]
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:ORPHAN",
                    name="ORPHAN",
                    scopes=({"kind": "shared-environment", "targets": ["production"]},),
                    kind=ValueKind.VARIABLE,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert delete.called
    body = json.loads(delete.calls[0].request.read())
    assert body == {"ids": ["env_orphan"]}
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"
