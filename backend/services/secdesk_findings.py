"""Redacted workspace findings with stable identities and explicit imports only."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select

from backend.events import EventHub
from backend.models import SecDeskFinding
from backend.services.workspace_service import WorkspaceService
from shared.secdesk import FindingImport, FindingImportResult, FindingView
from toolkit.secdesk.registry import load_registry


class SecDeskFindings:
    def __init__(self, workspaces: WorkspaceService, hub: EventHub) -> None:
        self.workspaces, self.hub = workspaces, hub
        self._lock = asyncio.Lock()
        self._pending = 0

    async def listing(self, workspace_id: UUID) -> list[FindingView]:
        async with await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                rows = await session.scalars(
                    select(SecDeskFinding).order_by(SecDeskFinding.created_at.desc()).limit(500)
                )
                return [FindingView.model_validate(row) for row in rows]

    async def import_records(self, data: FindingImport) -> FindingImportResult:
        if self._pending >= 32:
            raise ValueError("Findings queue full; wait for the active import")
        self._pending += 1
        try:
            async with self._lock:
                return await self._import(data)
        finally:
            self._pending -= 1

    async def _import(self, data: FindingImport) -> FindingImportResult:
        if data.tool_id not in {tool.id for tool in load_registry()}:
            raise ValueError("Select a registered source tool")
        inserted = 0
        async with await self.workspaces.lease(data.workspace_id) as lease:
            async with lease.sessions.begin() as session:
                for record in data.records:
                    fields = {
                        key: self.hub.redactor.text(value)
                        for key, value in record.model_dump().items()
                    }
                    digest = hashlib.sha256(
                        json.dumps(
                            [data.tool_id, fields["title"], fields["target"]],
                            ensure_ascii=False,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()
                    row = await session.scalar(
                        select(SecDeskFinding).where(SecDeskFinding.identity == digest)
                    )
                    if row is None:
                        row = SecDeskFinding(
                            id=str(uuid4()),
                            identity=digest,
                            tool_id=data.tool_id,
                            title=fields["title"],
                            target=fields["target"],
                            severity=fields["severity"],
                            evidence=fields["evidence"],
                            created_at=datetime.now(UTC),
                        )
                        session.add(row)
                        inserted += 1
                    else:
                        row.severity, row.evidence = fields["severity"], fields["evidence"]
        await self.hub.publish(
            "secdesk-findings",
            {"inserted": inserted, "imported": len(data.records)},
            workspace_id=data.workspace_id,
        )
        return FindingImportResult(inserted=inserted, merged=len(data.records) - inserted)
