"""Domain error codes and safe exceptions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SafeError:
    """Pre-redacted error suitable for presentation and reports."""

    code: str
    message: str
    hint: str | None = None
    destination_id: str | None = None
    mutation_id: str | None = None
    retryable: bool = False
    correlation_id: str | None = None


class SecretSyncError(Exception):
    """Base exception carrying a SafeError payload."""

    def __init__(self, safe: SafeError) -> None:
        self.safe = safe
        super().__init__(safe.message)

    @property
    def code(self) -> str:
        return self.safe.code


class ConfigInvalidError(SecretSyncError):
    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(SafeError(code="CONFIG_INVALID", message=message, hint=hint))


class UnimplementedChangeDetectionError(SecretSyncError):
    def __init__(self, strategy: str) -> None:
        super().__init__(
            SafeError(
                code="UNIMPLEMENTED_CHANGE_DETECTION",
                message=(
                    f"changeDetection '{strategy}' is not implemented; "
                    "MVP supports only 'always-write'"
                ),
                hint="Set changeDetection to always-write or omit it.",
            )
        )


class SourceMissingError(SecretSyncError):
    def __init__(self, env_name: str) -> None:
        super().__init__(
            SafeError(
                code="SOURCE_MISSING",
                message=f"Required environment variable '{env_name}' is absent",
                hint=f"Export {env_name} or inject it via your vault runner.",
            )
        )


class SourceEmptyError(SecretSyncError):
    def __init__(self, env_name: str) -> None:
        super().__init__(
            SafeError(
                code="SOURCE_EMPTY",
                message=f"Environment variable '{env_name}' is empty and allowEmpty is false",
            )
        )


class AuthMissingError(SecretSyncError):
    def __init__(self, env_name: str, *, destination_id: str | None = None) -> None:
        super().__init__(
            SafeError(
                code="AUTH_MISSING",
                message=f"Connector credential environment variable '{env_name}' is absent",
                destination_id=destination_id,
                hint=f"Export {env_name} before apply.",
            )
        )


class InvalidSecretValueError(SecretSyncError):
    def __init__(self, env_name: str, reason: str) -> None:
        super().__init__(
            SafeError(
                code="SOURCE_EMPTY" if reason == "empty" else "CONFIG_INVALID",
                message=f"Secret from '{env_name}' is invalid: {reason}",
            )
        )


class UnknownConnectorError(SecretSyncError):
    def __init__(self, connector_id: str) -> None:
        super().__init__(
            SafeError(
                code="CONFIG_INVALID",
                message=f"Unknown connector '{connector_id}'",
                hint="Use a built-in connector id once destinations are registered.",
            )
        )


# Stable exit codes from the Click contract (§3.4).
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_MISSING_ENV = 3
EXIT_CONNECTOR_VALIDATION = 4
EXIT_PARTIAL = 5
EXIT_ALL_FAILED = 6
EXIT_INTERRUPTED = 130

ERROR_EXIT_CODES: dict[str, int] = {
    "CONFIG_INVALID": EXIT_CONFIG,
    "UNIMPLEMENTED_CHANGE_DETECTION": EXIT_CONFIG,
    "SOURCE_MISSING": EXIT_MISSING_ENV,
    "SOURCE_EMPTY": EXIT_MISSING_ENV,
    "AUTH_MISSING": EXIT_MISSING_ENV,
}


def exit_code_for(error: SecretSyncError) -> int:
    return ERROR_EXIT_CODES.get(error.code, EXIT_CONFIG)
