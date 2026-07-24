"""Pydantic configuration schema (public YAML contract)."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class SecretDefinition(StrictModel):
    env: str
    allow_empty: bool = Field(default=False, alias="allowEmpty")

    @field_validator("env")
    @classmethod
    def env_must_be_valid(cls, value: str) -> str:
        if not value or not ENV_NAME_RE.match(value):
            msg = f"Invalid environment variable name: {value!r}"
            raise ValueError(msg)
        return value


class SecretOverride(StrictModel):
    env: str | None = None
    allow_empty: bool | None = Field(default=None, alias="allowEmpty")

    @field_validator("env")
    @classmethod
    def env_must_be_valid(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value or not ENV_NAME_RE.match(value):
            msg = f"Invalid environment variable name: {value!r}"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def at_least_one_field(self) -> SecretOverride:
        if self.env is None and self.allow_empty is None:
            msg = "Override must set env and/or allowEmpty"
            raise ValueError(msg)
        return self


class SetDefinition(StrictModel):
    extends: str | None = None
    include: list[str] = Field(default_factory=list)
    overrides: dict[str, SecretOverride] = Field(default_factory=dict)


class DestinationAuth(StrictModel):
    token_env: str = Field(alias="tokenEnv")

    @field_validator("token_env")
    @classmethod
    def token_env_valid(cls, value: str) -> str:
        if not value or not ENV_NAME_RE.match(value):
            msg = f"Invalid auth environment variable name: {value!r}"
            raise ValueError(msg)
        return value


class DestinationDefinition(StrictModel):
    connector: str
    auth: DestinationAuth | None = None
    # Connector-owned fields (repository, project, workingDirectory, …)
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    @model_validator(mode="before")
    @classmethod
    def require_connector(cls, data: Any) -> Any:
        if isinstance(data, dict) and "connector" not in data:
            msg = "destination.connector is required"
            raise ValueError(msg)
        return data


def _validate_publish_map(value: dict[str, str], field_name: str) -> dict[str, str]:
    for logical_id, dest_name in value.items():
        if not logical_id or not dest_name:
            msg = f"{field_name} keys and values must be non-empty"
            raise ValueError(msg)
    return value


class DeploymentDefinition(StrictModel):
    name: str
    set: str
    destination: str
    scope: dict[str, Any]
    secrets: dict[str, str] = Field(default_factory=dict)
    variables: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def name_non_empty(cls, value: str) -> str:
        if not value.strip():
            msg = "deployment name must be non-empty"
            raise ValueError(msg)
        return value

    @field_validator("secrets")
    @classmethod
    def secrets_map_valid(cls, value: dict[str, str]) -> dict[str, str]:
        return _validate_publish_map(value, "deployment.secrets")

    @field_validator("variables")
    @classmethod
    def variables_map_valid(cls, value: dict[str, str]) -> dict[str, str]:
        return _validate_publish_map(value, "deployment.variables")

    @model_validator(mode="after")
    def at_least_one_publish_map(self) -> DeploymentDefinition:
        if not self.secrets and not self.variables:
            msg = "deployment must declare secrets and/or variables mappings"
            raise ValueError(msg)
        return self


class RootConfig(StrictModel):
    version: Literal[1]
    change_detection: Literal["always-write", "keyed-fingerprint"] = Field(
        default="always-write",
        alias="changeDetection",
    )
    secrets: dict[str, SecretDefinition] = Field(default_factory=dict)
    variables: dict[str, SecretDefinition] = Field(default_factory=dict)
    sets: dict[str, SetDefinition] = Field(default_factory=dict)
    destinations: dict[str, DestinationDefinition]
    deployments: list[DeploymentDefinition]

    @model_validator(mode="after")
    def unique_deployment_names(self) -> RootConfig:
        names = [d.name for d in self.deployments]
        if len(names) != len(set(names)):
            msg = "deployment names must be unique"
            raise ValueError(msg)
        if not self.secrets and not self.variables:
            msg = "secrets and/or variables must declare at least one logical id"
            raise ValueError(msg)
        overlap = sorted(set(self.secrets) & set(self.variables))
        if overlap:
            listed = ", ".join(repr(i) for i in overlap)
            msg = (
                f"Logical ids must be unique across secrets and variables; "
                f"overlap: {listed}"
            )
            raise ValueError(msg)
        if not self.destinations:
            msg = "destinations must declare at least one destination"
            raise ValueError(msg)
        if not self.deployments:
            msg = "deployments must declare at least one deployment"
            raise ValueError(msg)
        return self
