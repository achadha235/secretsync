from __future__ import annotations

import pytest

from secretsync.domain.errors import InvalidSecretValueError, SourceEmptyError, SourceMissingError
from secretsync.domain.models import SecretRef
from secretsync.sources.environment import EnvironmentSource


@pytest.mark.asyncio
async def test_resolve_success() -> None:
    source = EnvironmentSource({"FOO": "bar"})
    material = await source.resolve(SecretRef(logical_id="foo", env_name="FOO"))
    assert material.value == bytearray(b"bar")


@pytest.mark.asyncio
async def test_resolve_missing() -> None:
    source = EnvironmentSource({})
    with pytest.raises(SourceMissingError):
        await source.resolve(SecretRef(logical_id="foo", env_name="FOO"))


@pytest.mark.asyncio
async def test_resolve_empty_rejected() -> None:
    source = EnvironmentSource({"FOO": ""})
    with pytest.raises(SourceEmptyError):
        await source.resolve(SecretRef(logical_id="foo", env_name="FOO"))


@pytest.mark.asyncio
async def test_resolve_empty_allowed() -> None:
    source = EnvironmentSource({"FOO": ""})
    material = await source.resolve(SecretRef(logical_id="foo", env_name="FOO", allow_empty=True))
    assert material.value == bytearray(b"")


@pytest.mark.asyncio
async def test_resolve_nul_rejected() -> None:
    source = EnvironmentSource({"FOO": "a\x00b"})
    with pytest.raises(InvalidSecretValueError):
        await source.resolve(SecretRef(logical_id="foo", env_name="FOO"))
