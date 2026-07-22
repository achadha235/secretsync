"""YAML configuration loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from secretsync.config.models import RootConfig
from secretsync.domain.errors import ConfigInvalidError


class ConfigLoader:
    """Parse and validate YAML into RootConfig."""

    def load(self, path: Path) -> RootConfig:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigInvalidError(f"Cannot read config file: {path}") from exc
        return self.load_text(text, source=str(path))

    def load_text(self, text: str, *, source: str = "<string>") -> RootConfig:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigInvalidError(f"Invalid YAML in {source}: {exc}") from exc
        if data is None:
            raise ConfigInvalidError(f"Config file is empty: {source}")
        if not isinstance(data, dict):
            raise ConfigInvalidError(f"Config root must be a mapping: {source}")
        return self.load_mapping(data, source=source)

    def load_mapping(self, data: dict[str, Any], *, source: str = "<mapping>") -> RootConfig:
        try:
            return RootConfig.model_validate(data)
        except ValidationError as exc:
            raise ConfigInvalidError(_format_validation_error(exc, source)) from exc


def _format_validation_error(exc: ValidationError, source: str) -> str:
    parts: list[str] = [f"Invalid configuration in {source}:"]
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        parts.append(f"  {loc}: {err['msg']}")
    return "\n".join(parts)
