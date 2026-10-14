"""Non-secret desktop preferences and summary contracts."""

from typing import Literal

from pydantic import Field

from shared.schemas import Identifier, SchemaModel


class DesktopSettings(SchemaModel):
    theme: Literal["dark", "light", "system"] = "dark"
    check_updates: bool = False
    onboarding_complete: bool = False
    dismissed_version: str = Field(
        default="", max_length=32, pattern=r"^(?:v?\d{1,6}\.\d{1,6}\.\d{1,6})?$"
    )


class UpdateNotice(SchemaModel):
    version: str = ""
    url: str = ""
    installer_url: str = ""
    installer_size: int = Field(default=0, ge=0)
    checksums_url: str = ""
    signature_url: str = ""
    checksums_signature_url: str = ""


class StartupUpdateResult(SchemaModel):
    state: Literal["checked", "disabled", "failed"]
    notice: UpdateNotice = Field(default_factory=UpdateNotice)


class UpdateRequest(SchemaModel):
    version: str = Field(max_length=32)


class UpdateProgress(SchemaModel):
    version: str = ""
    phase: Literal[
        "idle", "downloading", "verifying", "verified", "preparing", "prepared", "failed"
    ] = "idle"
    received: int = 0
    total: int = 0
    checksum_verified: bool = False
    signature_verified: bool = False
    message: str = ""
    can_apply: bool = False


class DashboardSummary(SchemaModel):
    workspace_id: Identifier
    targets: int
    recorded_sessions: int
    running_jobs: int
    saved_reports: int
