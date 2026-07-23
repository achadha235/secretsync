from __future__ import annotations

import pytest

from secretsync.domain.errors import (
    ERROR_EXIT_CODES,
    EXIT_CONFIG,
    EXIT_CONNECTOR_VALIDATION,
    EXIT_MISSING_ENV,
    EXIT_PARTIAL,
    AuthMissingError,
    ConfigInvalidError,
    ConnectorNotImplementedError,
    ConnectorValidationError,
    InvalidSecretValueError,
    SafeError,
    SecretSyncError,
    SourceEmptyError,
    SourceMissingError,
    UnimplementedChangeDetectionError,
    UnknownConnectorError,
    exit_code_for,
)


@pytest.mark.parametrize(
    ("code", "expected"),
    sorted(ERROR_EXIT_CODES.items()),
)
def test_exit_code_for_mapped_codes(code: str, expected: int) -> None:
    err = SecretSyncError(SafeError(code=code, message="x"))
    assert exit_code_for(err) == expected


def test_exit_code_for_unknown_defaults_to_config() -> None:
    err = SecretSyncError(SafeError(code="TOTALLY_NEW", message="x"))
    assert exit_code_for(err) == EXIT_CONFIG


def test_error_constructors_and_codes() -> None:
    assert ConfigInvalidError("bad", hint="h").code == "CONFIG_INVALID"
    assert UnimplementedChangeDetectionError("keyed-fingerprint").code == (
        "UNIMPLEMENTED_CHANGE_DETECTION"
    )
    assert SourceMissingError("FOO").code == "SOURCE_MISSING"
    assert SourceEmptyError("FOO").code == "SOURCE_EMPTY"
    assert AuthMissingError("TOKEN", destination_id="d1").safe.destination_id == "d1"
    assert InvalidSecretValueError("FOO", "empty").code == "SOURCE_EMPTY"
    assert InvalidSecretValueError("FOO", "nul").code == "CONFIG_INVALID"
    assert UnknownConnectorError("x").code == "CONFIG_INVALID"
    assert ConnectorNotImplementedError("vercel").code == "CONFIG_INVALID"
    assert ConnectorValidationError("nope", destination_id="d").code == "DESTINATION_INVALID"

    assert exit_code_for(SourceMissingError("X")) == EXIT_MISSING_ENV
    assert exit_code_for(AuthMissingError("T")) == EXIT_MISSING_ENV
    assert exit_code_for(ConnectorValidationError("x")) == EXIT_CONNECTOR_VALIDATION
    rate = SecretSyncError(SafeError(code="DESTINATION_RATE_LIMITED", message="r"))
    assert exit_code_for(rate) == EXIT_PARTIAL
    assert str(ConfigInvalidError("msg")) == "msg"
