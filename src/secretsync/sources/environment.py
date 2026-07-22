"""Environment-backed secret source."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from secretsync.domain.errors import InvalidSecretValueError, SourceEmptyError, SourceMissingError
from secretsync.domain.models import SecretMaterial, SecretRef


class SecretSource(Protocol):
    async def resolve(self, reference: SecretRef) -> SecretMaterial: ...


class EnvironmentSource:
    """Resolve secret values from a provided environment mapping."""

    def __init__(self, environ: Mapping[str, str]) -> None:
        self._environ = environ

    async def resolve(self, reference: SecretRef) -> SecretMaterial:
        raw = self._environ.get(reference.env_name)
        if raw is None:
            raise SourceMissingError(reference.env_name)
        if raw == "" and not reference.allow_empty:
            raise SourceEmptyError(reference.env_name)
        if "\x00" in raw:
            raise InvalidSecretValueError(reference.env_name, "NUL is not supported")
        return SecretMaterial(bytearray(raw.encode("utf-8")))

    def require_present(self, env_name: str) -> None:
        """Check presence without copying the value (validate phase)."""
        if env_name not in self._environ:
            raise SourceMissingError(env_name)
        value = self._environ[env_name]
        if value == "":
            # Presence-only check for validate; empty policy applied at resolve.
            pass
