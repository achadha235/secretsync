from __future__ import annotations

import base64

import httpx
import pytest
import respx
from nacl import public

from secretsync.application.services import create_services
from secretsync.destinations.base import ApplyDestinationRequest, OperationContext, PutMutation
from secretsync.destinations.github_actions import GitHubActionsFactory, encrypt_github_secret


def _services() -> object:
    return create_services({"GITHUB_TOKEN": "ghp_test_token"})


def _mutation(
    name: str,
    *,
    kind: str = "repository",
    environment: str | None = None,
) -> PutMutation:
    scope: dict[str, object] = {"kind": kind}
    if environment is not None:
        scope["environment"] = environment
    return PutMutation(
        mutation_id=f"dep:{name}",
        name=name,
        value=bytearray(b"SECRET_CANARY_gh"),
        scopes=(scope,),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_validate_requires_target_and_auth() -> None:
    dest = GitHubActionsFactory().create(_services())
    issues = await dest.validate({"connector": "github-actions"})
    assert any(i.code == "DESTINATION_INVALID" for i in issues)
    assert any(i.code == "AUTH_MISSING" for i in issues)


@pytest.mark.asyncio
@respx.mock
async def test_repository_put_created_and_updated() -> None:
    from nacl import encoding

    key = public.PrivateKey.generate().public_key
    key_b64 = key.encode(encoder=encoding.Base64Encoder).decode()
    respx.get("https://api.github.com/repos/acme/web/actions/secrets/public-key").mock(
        return_value=httpx.Response(200, json={"key_id": "key1", "key": key_b64})
    )
    respx.put("https://api.github.com/repos/acme/web/actions/secrets/DATABASE_URL").mock(
        return_value=httpx.Response(201)
    )
    respx.put("https://api.github.com/repos/acme/web/actions/secrets/API_TOKEN").mock(
        return_value=httpx.Response(204)
    )

    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[_mutation("DATABASE_URL"), _mutation("API_TOKEN")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 3  # 1 public key + 2 puts
    by_name = {r.mutation_id: r for r in result.results}
    assert by_name["dep:DATABASE_URL"].effect == "created"
    assert by_name["dep:API_TOKEN"].effect == "updated"
    assert all(r.status == "applied" for r in result.results)
    assert "SECRET_CANARY_gh" not in repr(result)


@pytest.mark.asyncio
@respx.mock
async def test_environment_url_encoding_and_key_cache() -> None:
    from nacl import encoding

    key = public.PrivateKey.generate().public_key
    key_b64 = key.encode(encoder=encoding.Base64Encoder).decode()
    env_key = respx.get(
        "https://api.github.com/repos/acme/web/environments/prod%2Fwest/secrets/public-key"
    ).mock(return_value=httpx.Response(200, json={"key_id": "k", "key": key_b64}))
    put1 = respx.put(
        "https://api.github.com/repos/acme/web/environments/prod%2Fwest/secrets/A"
    ).mock(return_value=httpx.Response(201))
    put2 = respx.put(
        "https://api.github.com/repos/acme/web/environments/prod%2Fwest/secrets/B"
    ).mock(return_value=httpx.Response(204))

    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[
                _mutation("A", kind="environment", environment="prod/west"),
                _mutation("B", kind="environment", environment="prod/west"),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert env_key.call_count == 1
    assert put1.called and put2.called
    assert result.requests_made == 3
    assert all(r.status == "applied" for r in result.results)


@pytest.mark.asyncio
@respx.mock
async def test_429_retried_on_put() -> None:
    from nacl import encoding

    key = public.PrivateKey.generate().public_key
    key_b64 = key.encode(encoder=encoding.Base64Encoder).decode()
    respx.get("https://api.github.com/repos/acme/web/actions/secrets/public-key").mock(
        return_value=httpx.Response(200, json={"key_id": "k", "key": key_b64})
    )
    respx.put("https://api.github.com/repos/acme/web/actions/secrets/A").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(201)]
    )
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[_mutation("A")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"


@pytest.mark.asyncio
async def test_organization_rejected() -> None:
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[_mutation("A", kind="organization")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "Organization" in result.results[0].error.message


def test_encrypt_roundtrip_shape() -> None:
    from nacl import encoding

    private = public.PrivateKey.generate()
    key_b64 = private.public_key.encode(encoder=encoding.Base64Encoder).decode()
    encrypted = encrypt_github_secret(key_b64, b"hello")
    # Ciphertext is base64 and decryptable with sealed box.
    box = public.SealedBox(private)
    plain = box.decrypt(base64.b64decode(encrypted))
    assert plain == b"hello"


@pytest.mark.asyncio
@respx.mock
async def test_list_names_repository() -> None:
    respx.get("https://api.github.com/repos/acme/web/actions/secrets").mock(
        return_value=httpx.Response(
            200,
            json={
                "total_count": 2,
                "secrets": [{"name": "A"}, {"name": "B"}],
            },
        )
    )
    dest = GitHubActionsFactory().create(_services())
    names = await dest.list_names(
        {
            "connector": "github-actions",
            "repository": "acme/web",
            "auth": {"tokenEnv": "GITHUB_TOKEN"},
        },
        {"kind": "repository"},
        OperationContext(correlation_id="c1"),
    )
    assert names == frozenset({"A", "B"})


@pytest.mark.asyncio
@respx.mock
async def test_delete_repository_secret() -> None:
    from secretsync.destinations.base import DeleteMutation

    route = respx.delete("https://api.github.com/repos/acme/web/actions/secrets/ORPHAN").mock(
        return_value=httpx.Response(204)
    )
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:ORPHAN",
                    name="ORPHAN",
                    scopes=({"kind": "repository"},),
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert route.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"


@pytest.mark.asyncio
@respx.mock
async def test_variable_create() -> None:
    from secretsync.domain.models import ValueKind

    route = respx.post("https://api.github.com/repos/acme/web/actions/variables").mock(
        return_value=httpx.Response(201)
    )
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[
                PutMutation(
                    mutation_id="dep:LOG_LEVEL",
                    name="LOG_LEVEL",
                    value=bytearray(b"info"),
                    scopes=({"kind": "repository"},),
                    kind=ValueKind.VARIABLE,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert route.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "created"
    body = route.calls[0].request.read()
    assert b'"name":"LOG_LEVEL"' in body or b'"name": "LOG_LEVEL"' in body
    assert b"info" in body


@pytest.mark.asyncio
@respx.mock
async def test_variable_update_on_conflict() -> None:
    from secretsync.domain.models import ValueKind

    respx.post("https://api.github.com/repos/acme/web/actions/variables").mock(
        return_value=httpx.Response(409)
    )
    patch = respx.patch("https://api.github.com/repos/acme/web/actions/variables/LOG_LEVEL").mock(
        return_value=httpx.Response(204)
    )
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[
                PutMutation(
                    mutation_id="dep:LOG_LEVEL",
                    name="LOG_LEVEL",
                    value=bytearray(b"debug"),
                    scopes=({"kind": "repository"},),
                    kind=ValueKind.VARIABLE,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert patch.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "updated"
    assert result.requests_made == 2


@pytest.mark.asyncio
@respx.mock
async def test_list_variable_names() -> None:
    from secretsync.domain.models import ValueKind

    respx.get("https://api.github.com/repos/acme/web/actions/variables").mock(
        return_value=httpx.Response(
            200,
            json={"total_count": 1, "variables": [{"name": "LOG_LEVEL", "value": "info"}]},
        )
    )
    dest = GitHubActionsFactory().create(_services())
    names = await dest.list_names(
        {
            "connector": "github-actions",
            "repository": "acme/web",
            "auth": {"tokenEnv": "GITHUB_TOKEN"},
        },
        {"kind": "repository"},
        OperationContext(correlation_id="c1"),
        kind=ValueKind.VARIABLE,
    )
    assert names == frozenset({"LOG_LEVEL"})


@pytest.mark.asyncio
@respx.mock
async def test_delete_variable() -> None:
    from secretsync.destinations.base import DeleteMutation
    from secretsync.domain.models import ValueKind

    route = respx.delete("https://api.github.com/repos/acme/web/actions/variables/ORPHAN").mock(
        return_value=httpx.Response(204)
    )
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "repository": "acme/web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[],
            deletes=[
                DeleteMutation(
                    mutation_id="dep:delete:ORPHAN",
                    name="ORPHAN",
                    scopes=({"kind": "repository"},),
                    kind=ValueKind.VARIABLE,
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert route.called
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "deleted"


def test_parse_github_target_allowed_forms() -> None:
    from secretsync.destinations.github_actions import GitHubRepoRef, _parse_github_target

    org_only = _parse_github_target({"organization": "acme"})
    assert org_only == GitHubRepoRef(owner="acme", repository=None)

    org_and_name = _parse_github_target({"organization": "acme", "repository": "web"})
    assert org_and_name == GitHubRepoRef(owner="acme", repository="web")

    shorthand = _parse_github_target({"repository": "acme/web"})
    assert shorthand == GitHubRepoRef(owner="acme", repository="web")


def test_parse_github_target_rejects_org_with_owner_repo() -> None:
    from secretsync.destinations.github_actions import _ConfigParseError, _parse_github_target

    redundant = _parse_github_target({"organization": "acme", "repository": "acme/web"})
    assert isinstance(redundant, _ConfigParseError)
    assert "must not set organization together" in redundant.message
    assert redundant.hint is not None
    assert "repository: 'web'" in redundant.hint

    mismatched = _parse_github_target({"organization": "acme", "repository": "other/web"})
    assert isinstance(mismatched, _ConfigParseError)
    assert "does not match" in mismatched.message
    assert "other" in mismatched.message


def test_parse_github_target_rejects_bare_repo_without_org() -> None:
    from secretsync.destinations.github_actions import _ConfigParseError, _parse_github_target

    bare = _parse_github_target({"repository": "web"})
    assert isinstance(bare, _ConfigParseError)
    assert "owner/name" in bare.message


@pytest.mark.asyncio
async def test_validate_accepts_organization_and_repo_name() -> None:
    dest = GitHubActionsFactory().create(_services())
    issues = await dest.validate(
        {
            "connector": "github-actions",
            "organization": "acme",
            "repository": "web",
            "auth": {"tokenEnv": "GITHUB_TOKEN"},
        }
    )
    assert issues == []


@pytest.mark.asyncio
async def test_validate_rejects_organization_with_owner_repo() -> None:
    dest = GitHubActionsFactory().create(_services())
    issues = await dest.validate(
        {
            "connector": "github-actions",
            "organization": "acme",
            "repository": "acme/web",
            "auth": {"tokenEnv": "GITHUB_TOKEN"},
        }
    )
    assert any(i.code == "DESTINATION_INVALID" for i in issues)
    assert any("must not set organization together" in i.message for i in issues)


@pytest.mark.asyncio
@respx.mock
async def test_apply_with_organization_and_repo_name() -> None:
    from nacl import encoding

    key = public.PrivateKey.generate().public_key
    key_b64 = key.encode(encoder=encoding.Base64Encoder).decode()
    respx.get("https://api.github.com/repos/acme/web/actions/secrets/public-key").mock(
        return_value=httpx.Response(200, json={"key_id": "key1", "key": key_b64})
    )
    respx.put("https://api.github.com/repos/acme/web/actions/secrets/DATABASE_URL").mock(
        return_value=httpx.Response(201)
    )
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "organization": "acme",
                "repository": "web",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[_mutation("DATABASE_URL")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "applied"
    assert result.results[0].effect == "created"


@pytest.mark.asyncio
async def test_org_only_destination_rejects_repo_scope_apply() -> None:
    dest = GitHubActionsFactory().create(_services())
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "github-actions",
                "organization": "acme",
                "auth": {"tokenEnv": "GITHUB_TOKEN"},
            },
            mutations=[_mutation("A")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "no repository" in result.results[0].error.message
