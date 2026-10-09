"""Validated payload generation and managed-artifact metadata."""

from pydantic import Field, field_validator

from shared.modules import ModulePath
from shared.schemas import Identifier, SchemaModel


class PayloadRequest(SchemaModel):
    workspace_id: Identifier
    framework_id: Identifier
    payload: str = Field(max_length=190)
    format: str = Field(min_length=1, max_length=40, pattern=r"^[A-Za-z0-9_-]+$")
    encoder: str = Field(default="", max_length=190)
    iterations: int = Field(default=1, ge=1, le=10)
    lhost: str = Field(max_length=100)
    lport: int = Field(ge=1, le=65535)
    confirmed: bool = False

    @field_validator("payload", "encoder")
    @classmethod
    def module_name(cls, value: str) -> str:
        if value:
            ModulePath(path="payload/" + value)
        return value


class PayloadCatalog(SchemaModel):
    formats: list[str]
    encoders: list[str]


class ArtifactView(SchemaModel):
    id: Identifier
    workspace_id: Identifier
    name: str
    media_type: str
    size_bytes: int
    sha256: str
