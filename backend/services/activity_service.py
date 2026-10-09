"""Immutable activity ownership; terminal streams stay in RAM and history omits arguments."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.models import ConsoleHistory, FrameworkInstance, JobAssociation, RemoteSession
from backend.mutations import MutationConflictError
from backend.services.module_service import ModuleService
from backend.services.rpc_transport import RpcFailure
from shared.activity import (
    ActivitySnapshot,
    ConsoleHandle,
    ConsoleOpen,
    RemoteAction,
    RemoteItem,
    TerminalCommand,
    TerminalOutput,
)


class ActivityService:
    def __init__(self, modules: ModuleService) -> None:
        self.modules = modules
        self._lock = asyncio.Lock()
        self._consoles: dict[tuple[UUID, UUID], str] = {}
        self._buffers: dict[tuple[UUID, UUID, str, str], deque[tuple[int, str]]] = {}
        self._sequence: dict[tuple[UUID, UUID, str, str], int] = {}

    def check(self, framework_id: UUID) -> None:
        if self.modules.identity() != str(framework_id):
            raise MutationConflictError("Framework identity changed. Refresh before interacting.")

    async def _owners(self, framework_id: UUID) -> dict[tuple[str, str], UUID]:
        owners: dict[tuple[str, str], UUID] = {}
        for workspace in await self.modules.workspaces.list():
            async with await self.modules.workspaces.lease(workspace.id) as lease:
                async with lease.sessions() as session:
                    for row in await session.scalars(
                        select(JobAssociation).where(
                            JobAssociation.framework_id == str(framework_id)
                        )
                    ):
                        if row.remote_job_id:
                            owners["job", row.remote_job_id] = workspace.id
                    for remote in await session.scalars(
                        select(RemoteSession).where(RemoteSession.framework_id == str(framework_id))
                    ):
                        owners["session", remote.remote_id] = workspace.id
        return owners

    async def _ensure_framework(self, session: AsyncSession, framework_id: UUID) -> None:
        if await session.get(FrameworkInstance, str(framework_id)) is None:
            session.add(
                FrameworkInstance(
                    id=str(framework_id),
                    identity=str(framework_id),
                    endpoint=self.modules.framework.status().endpoint,
                    created_at=datetime.now(UTC),
                )
            )
            await session.flush()

    async def snapshot(self, workspace_id: UUID) -> ActivitySnapshot:
        framework_id = UUID(self.modules.identity())
        await self.modules.workspaces.get(workspace_id)
        async with self._lock, self.modules.framework._connection_lock:
            self.check(framework_id)
            sessions = await self.modules.framework.get_sessions()
            jobs = await self.modules.framework.get_jobs()
            if len(sessions) + len(jobs) > 2000:
                raise ValueError("Remote activity exceeds 2000 entries")
            owners = await self._owners(framework_id)
            # Associate framework-created sessions through their immutable launch identity.
            for workspace in await self.modules.workspaces.list():
                async with await self.modules.workspaces.lease(workspace.id) as lease:
                    async with lease.sessions.begin() as session:
                        launches = {
                            row.execution_id: row
                            for row in await session.scalars(
                                select(JobAssociation).where(
                                    JobAssociation.framework_id == str(framework_id)
                                )
                            )
                            if row.execution_id
                        }
                        for remote_id, info in sessions.items():
                            if ("session", remote_id) in owners or not isinstance(info, dict):
                                continue
                            launch = launches.get(str(info.get("exploit_uuid", "")))
                            if launch and re.fullmatch(r"[0-9]{1,20}", remote_id):
                                session.add(
                                    RemoteSession(
                                        id=str(uuid4()),
                                        framework_id=str(framework_id),
                                        remote_id=remote_id,
                                        target_id=launch.target_id,
                                        job_id=launch.id,
                                        status="active",
                                        created_at=datetime.now(UTC),
                                    )
                                )
                                owners["session", remote_id] = workspace.id
            items: list[RemoteItem] = []
            for kind, entries in (("session", sessions), ("job", jobs)):
                for remote_id, raw in entries.items():
                    if not re.fullmatch(r"[0-9]{1,20}", remote_id):
                        raise ValueError("Invalid remote activity identity")
                    owner = owners.get((kind, remote_id))
                    if owner is not None and owner != workspace_id:
                        continue
                    info = raw if isinstance(raw, dict) else {}
                    items.append(
                        RemoteItem.model_validate(
                            {
                                "remote_id": remote_id,
                                "kind": kind,
                                "name": (
                                    str(info.get("type", "session"))
                                    if kind == "session"
                                    else self.modules.events.redactor.text(str(raw))[:200]
                                ),
                                "workspace_id": owner,
                                "session_type": str(info.get("type", ""))[:50],
                                "peer": self.modules.events.redactor.text(
                                    str(info.get("tunnel_peer", ""))
                                )[:200],
                            }
                        )
                    )
            return ActivitySnapshot(
                framework_id=framework_id, workspace_id=workspace_id, items=items
            )

    async def claim(self, data: RemoteAction) -> None:
        if not data.confirmed:
            raise ValueError("Confirm importing this activity into the selected workspace")
        async with self._lock, self.modules.framework._connection_lock:
            self.check(data.framework_id)
            owners = await self._owners(data.framework_id)
            owner = owners.get((data.kind, data.remote_id))
            if owner is not None and owner != data.workspace_id:
                raise MutationConflictError("Activity already belongs to another workspace.")
            entries = await (
                self.modules.framework.get_sessions()
                if data.kind == "session"
                else self.modules.framework.get_jobs()
            )
            if data.remote_id not in entries:
                raise KeyError("Remote activity ended")
            if owner is None:
                async with await self.modules.workspaces.lease(data.workspace_id) as lease:
                    async with lease.sessions.begin() as session:
                        await self._ensure_framework(session, data.framework_id)
                        if data.kind == "session":
                            session.add(
                                RemoteSession(
                                    id=str(uuid4()),
                                    framework_id=str(data.framework_id),
                                    remote_id=data.remote_id,
                                    target_id=None,
                                    job_id=None,
                                    status="active",
                                    created_at=datetime.now(UTC),
                                )
                            )
                        else:
                            session.add(
                                JobAssociation(
                                    id=str(uuid4()),
                                    framework_id=str(data.framework_id),
                                    remote_job_id=data.remote_id,
                                    execution_id=None,
                                    target_id=None,
                                    module_id="imported",
                                    status="active",
                                    created_at=datetime.now(UTC),
                                )
                            )

    async def _require_owner(
        self, workspace_id: UUID, framework_id: UUID, kind: str, remote_id: str
    ) -> None:
        if (await self._owners(framework_id)).get((kind, remote_id)) != workspace_id:
            raise MutationConflictError("Import this activity into its owning workspace first.")

    async def stop(self, data: RemoteAction) -> None:
        if not data.confirmed:
            raise ValueError("Explicit stop confirmation is required")
        async with self._lock, self.modules.framework._connection_lock:
            self.check(data.framework_id)
            await self._require_owner(
                data.workspace_id, data.framework_id, data.kind, data.remote_id
            )
            if data.kind == "session":
                await self.modules.framework.kill_session(data.remote_id)
            else:
                await self.modules.framework.kill_job(data.remote_id)
        await self.modules.events.publish(
            "activity",
            {"status": "stopped", "kind": data.kind, "remote_id": data.remote_id},
            workspace_id=data.workspace_id,
        )

    async def open_console(self, data: ConsoleOpen) -> ConsoleHandle:
        async with self._lock, self.modules.framework._connection_lock:
            self.check(data.framework_id)
            await self.modules.workspaces.get(data.workspace_id)
            key = data.workspace_id, data.framework_id
            if key not in self._consoles:
                if len(self._consoles) >= 16:
                    raise ValueError("Close unused consoles; maximum 16 per application")
                result = await self.modules.framework.call("console.create")
                identifier = str(result.get("id", ""))
                if not re.fullmatch(r"[0-9]{1,20}", identifier):
                    raise RpcFailure("Invalid console identity")
                self._consoles[key] = identifier
            return ConsoleHandle(**data.model_dump(), remote_id=self._consoles[key])

    async def _validate_terminal(self, data: TerminalCommand) -> None:
        self.check(data.framework_id)
        if data.kind == "console":
            if self._consoles.get((data.workspace_id, data.framework_id)) != data.remote_id:
                raise MutationConflictError("Console belongs to another workspace or instance.")
        else:
            await self._require_owner(
                data.workspace_id, data.framework_id, "session", data.remote_id
            )
            sessions = await self.modules.framework.get_sessions()
            info = sessions.get(data.remote_id)
            if not isinstance(info, dict) or info.get("type") != data.kind:
                raise ValueError("Session ended or has a different terminal type")

    async def command(self, data: TerminalCommand) -> None:
        command = data.command.get_secret_value()
        if not command.strip() or "\x00" in command or len(command) > 65536:
            raise ValueError("Invalid terminal command")
        async with self._lock, self.modules.framework._connection_lock:
            await self._validate_terminal(data)
            async with await self.modules.workspaces.lease(data.workspace_id) as lease:
                if data.kind == "console":
                    await self.modules.framework.call(
                        "console.write", [data.remote_id, command.rstrip("\n") + "\n"]
                    )
                else:
                    await self.modules.framework.interact_session(
                        data.remote_id, data.kind, command.rstrip("\n") + "\n"
                    )
                # Arbitrary command arguments can carry credentials without recognizable labels.
                # Store only a safe command name; never persist raw commands or terminal output.
                first = command.strip().split()[0]
                safe = (
                    first
                    if first
                    in {
                        "help",
                        "version",
                        "sessions",
                        "jobs",
                        "info",
                        "show",
                        "search",
                        "use",
                        "set",
                        "setg",
                        "get",
                        "unset",
                        "run",
                        "exploit",
                        "back",
                        "exit",
                        "pwd",
                        "ls",
                    }
                    else "[command]"
                )
                async with lease.sessions.begin() as session:
                    await self._ensure_framework(session, data.framework_id)
                    session.add(
                        ConsoleHistory(
                            id=str(uuid4()),
                            framework_id=str(data.framework_id),
                            redacted_text=safe + " [arguments redacted]",
                            created_at=datetime.now(UTC),
                        )
                    )
                    await session.flush()
                    old = list(
                        await session.scalars(
                            select(ConsoleHistory.id)
                            .order_by(ConsoleHistory.created_at.desc())
                            .offset(1000)
                        )
                    )
                    if old:
                        await session.execute(
                            delete(ConsoleHistory).where(ConsoleHistory.id.in_(old))
                        )
        await self.modules.events.publish(
            "terminal", {"status": "command submitted"}, workspace_id=data.workspace_id
        )

    async def output(self, data: TerminalCommand, since: int = 0) -> TerminalOutput:
        async with self._lock, self.modules.framework._connection_lock:
            await self._validate_terminal(data)
            key = data.workspace_id, data.framework_id, data.kind, data.remote_id
            if key not in self._buffers and len(self._buffers) >= 32:
                raise ValueError("Terminal capacity reached; close unused terminals")
            reply = await (
                self.modules.framework.call("console.read", [data.remote_id])
                if data.kind == "console"
                else self.modules.framework.interact_session(data.remote_id, data.kind)
            )
            text = reply.get("data", "")
            if not isinstance(text, str) or len(text) > 1024 * 1024:
                raise ValueError("Terminal output exceeded one MiB")
            buffer = self._buffers.setdefault(key, deque(maxlen=10000))
            for line in text.splitlines():
                sequence = self._sequence.get(key, 0) + 1
                self._sequence[key] = sequence
                buffer.append((sequence, self.modules.events.redactor.text(line)[:1000]))
            rows = [(number, line) for number, line in buffer if number > since]
            return TerminalOutput(
                lines=[line for _, line in rows],
                sequence=self._sequence.get(key, 0),
                truncated=bool(buffer and since < buffer[0][0] - 1),
            )

    async def history(self, workspace_id: UUID) -> list[str]:
        async with await self.modules.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                return list(
                    await session.scalars(
                        select(ConsoleHistory.redacted_text)
                        .order_by(ConsoleHistory.created_at.desc())
                        .limit(1000)
                    )
                )

    async def close_console(self, data: ConsoleHandle) -> None:
        async with self._lock, self.modules.framework._connection_lock:
            self.check(data.framework_id)
            key = data.workspace_id, data.framework_id
            if self._consoles.get(key) != data.remote_id:
                raise MutationConflictError("Console belongs to another workspace.")
            await self.modules.framework.call("console.destroy", [data.remote_id])
            self._consoles.pop(key)
            stream = (*key, "console", data.remote_id)
            self._buffers.pop(stream, None)
            self._sequence.pop(stream, None)

    async def close(self) -> None:
        # Destroy only API consoles owned here, never externally managed sessions/jobs.
        for (_, framework_id), identifier in tuple(self._consoles.items()):
            try:
                self.check(framework_id)
                await self.modules.framework.call("console.destroy", [identifier])
            except (RpcFailure, ValueError, MutationConflictError):
                pass
        self._consoles.clear()
        self._buffers.clear()
        self._sequence.clear()
