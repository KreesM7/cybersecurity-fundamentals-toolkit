"""Explicit native launch and bounded, workspace-owned terminal contracts."""

from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, SecretStr, field_validator

from shared.schemas import Identifier, SchemaModel
from toolkit.secdesk.findings import FindingRecord


class NativeLaunch(SchemaModel):
    workspace_id: Identifier
    tool_id: str = Field(min_length=1, max_length=64)
    mode: Literal["terminal", "gui"]
    authorized: bool = False  # Legacy client field; never required for a launch.


class NativeHandle(SchemaModel):
    id: Identifier
    workspace_id: Identifier


class NativeSnapshot(NativeHandle):
    tool_id: str
    mode: Literal["terminal", "gui"]
    status: Literal["running", "exited", "closed", "failed"]
    screen: str = ""
    message: str = ""
    rows: int = 24
    columns: int = 80


class NativeInput(NativeHandle):
    text: SecretStr = Field(min_length=1, max_length=4096, repr=False)

    def transport_dump(self) -> dict[str, str]:
        return {
            "id": str(self.id),
            "workspace_id": str(self.workspace_id),
            "text": self.text.get_secret_value(),
        }


class NativeResize(NativeHandle):
    rows: int = Field(ge=2, le=60)
    columns: int = Field(ge=10, le=200)


class NativeAudit(SchemaModel):
    id: Identifier
    tool_id: str
    mode: str
    event: str
    authorized: bool
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class FindingSource(SchemaModel):
    workspace_id: Identifier
    tool_id: str = Field(min_length=1, max_length=64)


class FindingImport(FindingSource):
    records: list[FindingRecord] = Field(min_length=1, max_length=1000)


class FindingImportResult(SchemaModel):
    inserted: int
    merged: int


class FindingView(SchemaModel):
    id: Identifier
    tool_id: str
    title: str
    severity: str
    target: str
    evidence: str
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
