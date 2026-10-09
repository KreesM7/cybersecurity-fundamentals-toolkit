"""Module browser contracts. Option values are ephemeral and never included in history."""

import re
from typing import Literal

from pydantic import Field, JsonValue, field_validator

from shared.schemas import Identifier, SchemaModel

ModuleKind = Literal["", "auxiliary", "exploit", "post", "payload", "encoder", "nop", "evasion"]
Rank = Literal["", "manual", "low", "average", "normal", "good", "great", "excellent"]


class ModulePath(SchemaModel):
    path: str = Field(min_length=3, max_length=200)

    @field_validator("path")
    @classmethod
    def valid_path(cls, value: str) -> str:
        if not re.fullmatch(
            r"(?:auxiliary|exploit|post|payload|encoder|nop|evasion)/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*",
            value,
        ):
            raise ValueError("Invalid module path")
        return value


class ModuleSummary(ModulePath):
    name: str = Field(max_length=1000)
    kind: ModuleKind
    rank: str = Field(max_length=30)


class ModuleSearch(SchemaModel):
    modules: list[ModuleSummary]
    truncated: bool = False


class OptionSpec(SchemaModel):
    name: str
    kind: str = "string"
    required: bool = False
    description: str = ""
    default: str | int | float | bool | None = None
    choices: list[str] = Field(default_factory=list)
    secret: bool = False


class ModuleDetail(ModulePath):
    framework_id: Identifier
    name: str
    description: str
    options: list[OptionSpec]
    payloads: list[str] = Field(default_factory=list)


class ModuleLibrary(SchemaModel):
    favorites: list[str] = Field(default_factory=list)
    recent: list[str] = Field(default_factory=list)


class FavoriteChange(ModulePath):
    enabled: bool


class ModuleRun(ModulePath):
    framework_id: Identifier
    workspace_id: Identifier
    target_id: Identifier | None = None
    options: dict[str, str | int | float | bool] = Field(default_factory=dict, max_length=200)
    confirmed: bool = False


class ModuleLaunch(ModulePath):
    id: Identifier
    workspace_id: Identifier
    framework_id: Identifier
    remote_job_id: str | None = None
    execution_id: str | None = None
    status: str


class ObjectReply(SchemaModel):
    """Explicit wrapper for extensible JSON snapshots (never a free-form RPC proxy)."""

    data: dict[str, JsonValue] = Field(default_factory=dict)
