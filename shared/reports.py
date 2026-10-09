"""Bounded report requests; report templates and storage paths are server-owned."""

from typing import Literal

from shared.schemas import Identifier, Name, SchemaModel


class ReportRequest(SchemaModel):
    workspace_id: Identifier
    title: Name = "Workspace assessment"
    format: Literal["html", "pdf"] = "html"
    include_notes: bool = False
