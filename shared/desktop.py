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


class DashboardSummary(SchemaModel):
    workspace_id: Identifier
    targets: int
    recorded_sessions: int
    running_jobs: int
    saved_reports: int
