"""Integration tests for aws-ssm with a recording mock boto3 client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from secretsync.destinations.aws_ssm import AwsSsmDestination, AwsSsmFactory
from secretsync.destinations.base import (
    ApplyDestinationRequest,
    DeleteMutation,
    ListNamesError,
    OperationContext,
    PutMutation,
)
from secretsync.domain.models import ValueKind


@dataclass
class FakeSsmClient:
    puts: list[dict[str, Any]] = field(default_factory=list)
    deletes: list[list[str]] = field(default_factory=list)
    describe_pages: list[dict[str, Any]] = field(default_factory=list)
    describe_calls: list[dict[str, Any]] = field(default_factory=list)
    fail_put_with: Exception | None = None
    fail_delete_with: Exception | None = None
    fail_describe_with: Exception | None = None
    _describe_idx: int = 0

    def put_parameter(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail_put_with is not None:
            raise self.fail_put_with
        self.puts.append(dict(kwargs))
        return {"Version": 1, "Tier": kwargs.get("Tier", "Standard")}

    def delete_parameters(self, *, Names: list[str]) -> dict[str, Any]:
        if self.fail_delete_with is not None:
            raise self.fail_delete_with
        self.deletes.append(list(Names))
        return {"DeletedParameters": list(Names), "InvalidParameters": []}

    def describe_parameters(self, **kwargs: Any) -> dict[str, Any]:
        if self.fail_describe_with is not None:
            raise self.fail_describe_with
        self.describe_calls.append(dict(kwargs))
        if self._describe_idx >= len(self.describe_pages):
            return {"Parameters": []}
        page = self.describe_pages[self._describe_idx]
        self._describe_idx += 1
        return page


def _dest(client: FakeSsmClient, *, region: str | None = "us-east-1") -> AwsSsmDestination:
    seen: dict[str | None, str | None] = {}

    def factory(requested_region: str | None) -> FakeSsmClient:
        seen["region"] = requested_region
        assert requested_region == region
        return client

    dest = AwsSsmDestination(
        manifest=AwsSsmFactory().manifest,
        environ={"AWS_REGION": region or "us-east-1"},
        client_factory=factory,
    )
    return dest


def _put(
    name: str,
    value: bytes = b"SECRET_CANARY_ssm",
    *,
    kind: ValueKind = ValueKind.SECRET,
    path_prefix: str = "/myapp/prod",
) -> PutMutation:
    return PutMutation(
        mutation_id=f"dep:{name}",
        name=name,
        value=bytearray(value),
        scopes=({"pathPrefix": path_prefix},),
        kind=kind,
    )


def _delete(name: str, *, path_prefix: str = "/myapp/prod") -> DeleteMutation:
    return DeleteMutation(
        mutation_id=f"dep:del:{name}",
        name=name,
        scopes=({"pathPrefix": path_prefix},),
    )


@pytest.mark.asyncio
async def test_put_secure_string_and_string() -> None:
    client = FakeSsmClient()
    dest = _dest(client)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={
                "connector": "aws-ssm",
                "region": "us-east-1",
                "keyId": "alias/my-key",
                "tier": "Advanced",
            },
            mutations=[
                _put("API_KEY", b"super-secret"),
                _put("LOG_LEVEL", b"info", kind=ValueKind.VARIABLE),
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 2
    assert all(r.status == "applied" and r.effect == "upserted" for r in result.results)
    assert client.puts[0]["Name"] == "/myapp/prod/API_KEY"
    assert client.puts[0]["Type"] == "SecureString"
    assert client.puts[0]["KeyId"] == "alias/my-key"
    assert client.puts[0]["Overwrite"] is True
    assert client.puts[0]["Tier"] == "Advanced"
    assert client.puts[0]["Value"] == "super-secret"
    assert client.puts[1]["Name"] == "/myapp/prod/LOG_LEVEL"
    assert client.puts[1]["Type"] == "String"
    assert "KeyId" not in client.puts[1]


@pytest.mark.asyncio
async def test_put_failure_redacts_secret_in_error() -> None:
    client = FakeSsmClient(fail_put_with=RuntimeError("boom super-secret leaked"))
    dest = _dest(client)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={"connector": "aws-ssm", "region": "us-east-1"},
            mutations=[_put("API_KEY", b"super-secret")],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert "super-secret" not in result.results[0].error.message
    assert "***" in result.results[0].error.message


@pytest.mark.asyncio
async def test_list_names_strips_prefix_and_filters_type() -> None:
    client = FakeSsmClient(
        describe_pages=[
            {
                "Parameters": [
                    {"Name": "/myapp/prod/API_KEY", "Type": "SecureString"},
                    {"Name": "/myapp/prod/nested/TOKEN", "Type": "SecureString"},
                    {"Name": "/other/SKIP", "Type": "SecureString"},
                ],
                "NextToken": "page2",
            },
            {
                "Parameters": [
                    {"Name": "/myapp/prod/THIRD", "Type": "SecureString"},
                ],
            },
        ]
    )
    dest = _dest(client)
    names = await dest.list_names(
        {"connector": "aws-ssm", "region": "us-east-1"},
        {"pathPrefix": "/myapp/prod"},
        OperationContext(correlation_id="c1"),
        kind=ValueKind.SECRET,
    )
    assert names == frozenset({"API_KEY", "nested/TOKEN", "THIRD"})
    assert len(client.describe_calls) == 2
    filters = client.describe_calls[0]["ParameterFilters"]
    assert {"Key": "Name", "Option": "BeginsWith", "Values": ["/myapp/prod"]} in filters
    assert {"Key": "Type", "Option": "Equals", "Values": ["SecureString"]} in filters


@pytest.mark.asyncio
async def test_list_names_requires_path_prefix() -> None:
    dest = _dest(FakeSsmClient())
    with pytest.raises(ListNamesError) as excinfo:
        await dest.list_names(
            {"connector": "aws-ssm", "region": "us-east-1"},
            {},
            OperationContext(correlation_id="c1"),
        )
    assert "pathPrefix" in excinfo.value.safe.message


@pytest.mark.asyncio
async def test_delete_batches_by_ten() -> None:
    client = FakeSsmClient()
    dest = _dest(client)
    deletes = [_delete(f"NAME_{i}") for i in range(12)]
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={"connector": "aws-ssm", "region": "us-east-1"},
            mutations=[],
            deletes=deletes,
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 2
    assert all(r.status == "applied" and r.effect == "deleted" for r in result.results)
    assert len(client.deletes) == 2
    assert len(client.deletes[0]) == 10
    assert len(client.deletes[1]) == 2
    assert client.deletes[0][0] == "/myapp/prod/NAME_0"


@pytest.mark.asyncio
async def test_missing_scope_fails_put() -> None:
    client = FakeSsmClient()
    dest = _dest(client)
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={"connector": "aws-ssm", "region": "us-east-1"},
            mutations=[
                PutMutation(
                    mutation_id="dep:X",
                    name="X",
                    value=bytearray(b"v"),
                    scopes=(),
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.results[0].status == "failed"
    assert result.requests_made == 0
    assert client.puts == []
