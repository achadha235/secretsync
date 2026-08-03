"""Unit tests for aws-ssm helpers and missing-boto3 path."""

from __future__ import annotations

from typing import Any

import pytest

from secretsync.destinations.aws_ssm import (
    BOTO3_INSTALL_HINT,
    AwsSsmDestination,
    AwsSsmFactory,
    _default_ssm_client,
    join_parameter_name,
    parameter_type_for_kind,
    relative_parameter_name,
    validate_full_name,
    validate_relative_name,
)
from secretsync.destinations.base import (
    ApplyDestinationRequest,
    OperationContext,
    PutMutation,
)
from secretsync.domain.errors import SafeError
from secretsync.domain.models import ValueKind


def test_parameter_type_for_kind() -> None:
    assert parameter_type_for_kind(ValueKind.SECRET) == "SecureString"
    assert parameter_type_for_kind(ValueKind.VARIABLE) == "String"


def test_join_and_relative_parameter_name() -> None:
    assert join_parameter_name("/myapp/prod", "API_KEY") == "/myapp/prod/API_KEY"
    assert join_parameter_name("myapp/prod", "nested/KEY") == "/myapp/prod/nested/KEY"
    assert relative_parameter_name("/myapp/prod", "/myapp/prod/API_KEY") == "API_KEY"
    assert relative_parameter_name("/myapp/prod", "/myapp/prod/nested/KEY") == "nested/KEY"
    assert relative_parameter_name("/myapp/prod", "/other/API_KEY") is None
    assert relative_parameter_name("/myapp/prod", "/myapp/prod") is None


def test_validate_names() -> None:
    assert validate_relative_name("API_KEY") is None
    assert validate_relative_name("nested/KEY-1") is None
    assert validate_relative_name("/absolute") is not None
    assert validate_relative_name("bad name") is not None
    assert validate_full_name("/myapp/prod/API_KEY") is None
    assert validate_full_name("/aws/foo") is not None
    assert validate_full_name("/ssm/foo") is not None


@pytest.mark.asyncio
async def test_validate_rejects_bad_tier() -> None:
    dest = AwsSsmFactory().create(services=type("S", (), {"environ": {}})())
    issues = await dest.validate({"connector": "aws-ssm", "tier": "Premium"})
    assert any("tier" in i.message for i in issues)


@pytest.mark.asyncio
async def test_missing_boto3_apply_error() -> None:
    from secretsync.destinations.aws_ssm import Boto3MissingError

    def boom(region: str | None) -> Any:
        del region
        raise Boto3MissingError(
            SafeError(
                code="DEPENDENCY_MISSING",
                message="boto3 is required for the aws-ssm connector",
                hint=BOTO3_INSTALL_HINT,
            )
        )

    dest = AwsSsmDestination(
        manifest=AwsSsmFactory().manifest,
        environ={},
        client_factory=boom,
    )
    result = await dest.apply(
        ApplyDestinationRequest(
            deployment_id="dep",
            destination_config={"connector": "aws-ssm"},
            mutations=[
                PutMutation(
                    mutation_id="dep:API_KEY",
                    name="API_KEY",
                    value=bytearray(b"secret"),
                    scopes=({"pathPrefix": "/myapp/prod"},),
                )
            ],
        ),
        OperationContext(correlation_id="c1"),
    )
    assert result.requests_made == 0
    assert result.results[0].status == "failed"
    assert result.results[0].error is not None
    assert result.results[0].error.code == "DEPENDENCY_MISSING"
    assert "secretsync-cli[aws]" in (result.results[0].error.hint or "")


def test_default_client_factory_imports_boto3() -> None:
    # Dev group installs boto3; ensure the default factory can construct a client object.
    client = _default_ssm_client("us-east-1")
    assert client is not None
    assert client.meta.service_model.service_name == "ssm"


def test_factory_create() -> None:
    services = type("S", (), {"environ": {"AWS_REGION": "us-east-1"}})()
    dest = AwsSsmFactory().create(services)
    assert dest.manifest.id == "aws-ssm"
    assert dest.check_kind_support(ValueKind.SECRET) is None
    assert dest.check_kind_support(ValueKind.VARIABLE) is None
