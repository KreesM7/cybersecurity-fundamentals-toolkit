"""Strict tool inputs; secret transport is explicitly separate from reporting."""

from datetime import datetime
from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import Field, JsonValue, RootModel, SecretStr, TypeAdapter, field_validator

from shared.schemas import SchemaModel


class CaesarOptions(SchemaModel):
    kind: Literal["caesar"] = "caesar"
    text: Annotated[str, Field(max_length=100000)]
    shift: Annotated[int, Field(ge=1, le=25)] = 3
    decrypt: bool = False


class PasswordOptions(SchemaModel):
    kind: Literal["password-strength"] = "password-strength"
    password: SecretStr = Field(repr=False)

    @field_validator("password")
    @classmethod
    def length(cls, value: SecretStr) -> SecretStr:
        if not 1 <= len(value.get_secret_value()) <= 72:
            raise ValueError("Enter 1 to 72 characters; input is never truncated.")
        return value

    def transport_dump(self) -> dict[str, str]:
        return {"kind": self.kind, "password": self.password.get_secret_value()}


class InterfaceView(SchemaModel):
    name: str
    ip: str
    netmask: str


class ScannerOptions(SchemaModel):
    kind: Literal["network-scanner"] = "network-scanner"
    target: Annotated[str, Field(min_length=1, max_length=64)]
    interface: InterfaceView | None = None
    authorized: bool = False


class SQLField(SchemaModel):
    name: Annotated[str, Field(min_length=1, max_length=1000)]
    value: Annotated[str, Field(max_length=65536)] = ""


class SQLForm(SchemaModel):
    action: str
    method: Literal["GET", "POST"]
    fields: list[SQLField]
    probe_indices: list[int]


class SQLOptions(SchemaModel):
    kind: Literal["sql-checker"] = "sql-checker"
    operation: Literal["discover", "test"] = "discover"
    url: Annotated[str, Field(min_length=1, max_length=4096)]
    owned: bool = False
    allow_post: bool = False
    generation: Annotated[int, Field(ge=0)] = 0
    discovery_id: Annotated[UUID | None, Field(strict=False)] = None
    form_index: Annotated[int, Field(ge=0, le=19)] = 0
    fields: Annotated[list[SQLField], Field(max_length=100)] = Field(default_factory=list)


class DoSOptions(SchemaModel):
    kind: Literal["dos-detector"] = "dos-detector"
    threshold: Annotated[int, Field(ge=1, le=1000000)] = 100


class AnomalyOptions(SchemaModel):
    kind: Literal["anomaly-detector"] = "anomaly-detector"
    bin_seconds: Annotated[int, Field(ge=1, le=3600)] = 1
    baseline_bins: Annotated[int, Field(ge=2, le=120)] = 30
    threshold: Annotated[float, Field(ge=0.1, le=20, allow_inf_nan=False)] = 3.0


class FileOptions(SchemaModel):
    kind: Literal["file-type"] = "file-type"


ToolOptions: TypeAlias = Annotated[
    CaesarOptions
    | PasswordOptions
    | ScannerOptions
    | SQLOptions
    | DoSOptions
    | AnomalyOptions
    | FileOptions,
    Field(discriminator="kind"),
]
options_adapter: TypeAdapter[ToolOptions] = TypeAdapter(ToolOptions)


class ToolView(SchemaModel):
    id: str
    title: str
    order: int
    available: bool
    reason: str = ""


class ToolsList(RootModel[list[ToolView]]):
    pass


class InterfacesList(RootModel[list[InterfaceView]]):
    pass


class ToolJob(SchemaModel):
    id: UUID
    workspace_id: UUID
    tool_id: str
    status: str
    created_at: datetime
    updated_at: datetime
    progress: str = ""
    result: JsonValue = None
    error: str | None = None


class EmptyResponse(SchemaModel):
    pass
