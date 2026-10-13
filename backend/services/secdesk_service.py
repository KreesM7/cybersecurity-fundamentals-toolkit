"""Bounded native process supervision; launches never follow a passive doctor check."""

from __future__ import annotations

import asyncio
import importlib
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar
from uuid import UUID, uuid4

from sqlalchemy import select

from backend.events import EventHub
from backend.jobs import _drain
from backend.models import SecDeskAudit
from backend.platform_utils import protect_private_path
from backend.services.workspace_service import WorkspaceLease, WorkspaceService
from shared.secdesk import (
    NativeAudit,
    NativeHandle,
    NativeInput,
    NativeLaunch,
    NativeResize,
    NativeSnapshot,
)
from toolkit.secdesk.gui_process import NativeGUI
from toolkit.secdesk.registry import load_registry, locate_binary
from toolkit.secdesk.terminal import NativeTerminal

T = TypeVar("T")


async def native_call(function: Callable[[], T]) -> T:
    task = asyncio.create_task(asyncio.to_thread(function))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        await _drain(task)
        raise


@dataclass
class OwnedNative:
    snapshot: NativeSnapshot
    lease: WorkspaceLease
    terminal: NativeTerminal | None
    process: NativeGUI | None
    screen: Any
    stream: Any
    lock: asyncio.Lock
    monitor: asyncio.Task[None] | None = None
    released: bool = False
    permission_acknowledged: bool = False


class SecDeskService:
    def __init__(self, workspaces: WorkspaceService, hub: EventHub) -> None:
        self.workspaces, self.hub = workspaces, hub
        self.owned: dict[UUID, OwnedNative] = {}
        self._lock = asyncio.Lock()
        self._closed = False

    async def _audit(self, item: OwnedNative, event: str) -> None:
        async with item.lease.sessions.begin() as session:
            session.add(
                SecDeskAudit(
                    id=str(uuid4()),
                    tool_id=item.snapshot.tool_id,
                    mode=item.snapshot.mode,
                    event=event,
                    authorized=item.permission_acknowledged,
                    created_at=datetime.now(UTC),
                )
            )
        await self.hub.publish(
            "secdesk",
            {"tool_id": item.snapshot.tool_id, "event": event},
            workspace_id=item.snapshot.workspace_id,
        )

    async def audit(self, workspace_id: UUID) -> list[NativeAudit]:
        async with await self.workspaces.lease(workspace_id) as lease:
            async with lease.sessions() as session:
                rows = await session.scalars(
                    select(SecDeskAudit).order_by(SecDeskAudit.created_at.desc()).limit(200)
                )
                return [NativeAudit.model_validate(row) for row in rows]

    async def open(self, data: NativeLaunch) -> NativeSnapshot:
        tool = next((tool for tool in load_registry() if tool.id == data.tool_id), None)
        if tool is None:
            raise ValueError("Registered tool required")
        if data.mode == "terminal" and not tool.has_terminal:
            raise ValueError("Tool has no terminal interface")
        if data.mode == "gui" and not tool.native_gui:
            raise ValueError("Use the configured web console or tool documentation")
        located = await native_call(lambda: locate_binary(tool, terminal=data.mode == "terminal"))
        if not located:
            raise ValueError("Native tool not found; review Setup and recheck")
        async with self._lock:
            if self._closed or sum(not item.released for item in self.owned.values()) >= 4:
                raise ValueError("Native launch capacity reached; close a running tool")
            if len(self.owned) >= 100:
                old = next((key for key, item in self.owned.items() if item.released), None)
                if old is not None:
                    del self.owned[old]
            lease = await self.workspaces.lease(data.workspace_id)
            terminal = None
            process = None
            item = None
            try:
                directory = (
                    self.workspaces.profile / "workspaces" / str(data.workspace_id) / "native"
                )
                await native_call(lambda: protect_private_path(directory, directory=True))
                pyte = None
                if data.mode == "terminal":
                    try:
                        pyte = importlib.import_module("pyte")
                    except ImportError as error:
                        raise ValueError("Terminal renderer missing; reinstall pyte") from error
                    shell = (
                        str(Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32/cmd.exe")
                        if os.name == "nt"
                        else shutil.which("sh")
                    )
                    if not shell or not Path(shell).is_file():
                        raise ValueError("Native command shell unavailable")

                    def create_terminal() -> NativeTerminal:
                        nonlocal terminal
                        terminal = NativeTerminal(
                            [shell, "/D"] if os.name == "nt" else [shell],
                            directory,
                            extra_path=Path(located).parent,
                        )
                        return terminal

                    await native_call(create_terminal)
                else:
                    if os.name == "nt" and Path(located).suffix.lower() != ".exe":
                        raise ValueError("Native GUI requires an executable, not a shell script")

                    def create_gui() -> NativeGUI:
                        nonlocal process
                        process = NativeGUI([located], directory)
                        return process

                    await native_call(create_gui)
                screen = pyte.Screen(80, 24) if pyte else None
                item = OwnedNative(
                    NativeSnapshot(
                        id=uuid4(),
                        workspace_id=data.workspace_id,
                        tool_id=tool.id,
                        mode=data.mode,
                        status="running",
                    ),
                    lease,
                    terminal,
                    process,
                    screen,
                    pyte.Stream(screen) if pyte else None,
                    asyncio.Lock(),
                    permission_acknowledged=data.authorized,
                )
                # A launch without a durable acknowledgment is not accepted.
                await self._audit(item, "launched")
                self.owned[item.snapshot.id] = item
                item.monitor = asyncio.create_task(self._monitor(item))
                return item.snapshot.model_copy()
            except BaseException:
                try:
                    if terminal is not None:
                        await native_call(terminal.close)
                    if process is not None:
                        await native_call(process.close)
                except BaseException:
                    # Preserve ownership if rollback itself fails; the session list
                    # and shutdown can retry cleanup, and workspace deletion stays blocked.
                    if item is None:
                        item = OwnedNative(
                            NativeSnapshot(
                                id=uuid4(),
                                workspace_id=data.workspace_id,
                                tool_id=tool.id,
                                mode=data.mode,
                                status="failed",
                            ),
                            lease,
                            terminal,
                            process,
                            None,
                            None,
                            asyncio.Lock(),
                            permission_acknowledged=data.authorized,
                        )
                    item.snapshot.status = "failed"
                    self.owned[item.snapshot.id] = item
                    raise
                await lease.release()
                raise

    def _get(self, handle: NativeHandle) -> OwnedNative:
        item = self.owned.get(handle.id)
        if item is None or item.snapshot.workspace_id != handle.workspace_id:
            raise ValueError("Native session unavailable in this workspace")
        return item

    def snapshot(self, handle: NativeHandle) -> NativeSnapshot:
        return self._get(handle).snapshot.model_copy()

    async def input(self, data: NativeInput) -> NativeSnapshot:
        item = self._get(data)
        async with item.lock:
            if item.released or item.terminal is None or item.snapshot.status != "running":
                raise ValueError("Terminal is closed or unavailable")
            terminal = item.terminal
            await native_call(lambda: terminal.write(data.text.get_secret_value()))
            return item.snapshot.model_copy()

    async def resize(self, data: NativeResize) -> NativeSnapshot:
        item = self._get(data)
        async with item.lock:
            if item.released or item.terminal is None or item.snapshot.status != "running":
                raise ValueError("Terminal is closed or unavailable")
            terminal = item.terminal
            await native_call(lambda: terminal.resize(data.rows, data.columns))
            item.screen.resize(lines=data.rows, columns=data.columns)
            item.snapshot.rows, item.snapshot.columns = data.rows, data.columns
            self._render(item)
            return item.snapshot.model_copy()

    def _render(self, item: OwnedNative) -> None:
        # Native terminals soft-wrap credentials, even in the middle of a key.
        # Redact the continuous fixed-width screen before restoring visual rows.
        width = item.snapshot.columns
        logical = "".join(
            line if len(line.rstrip()) == width else line.rstrip() + "\n"
            for line in item.screen.display
        )
        safe = self.hub.redactor.text(logical)
        rows: list[str] = []
        for line in safe.splitlines():
            rows.extend(line[index : index + width] for index in range(0, len(line), width))
            if not line:
                rows.append("")
        item.snapshot.screen = "\n".join(rows[: item.snapshot.rows])

    async def _monitor(self, item: OwnedNative) -> None:
        try:
            while True:
                async with item.lock:
                    if item.terminal:
                        text = await native_call(item.terminal.read)
                        if text:
                            item.stream.feed(text)
                            self._render(item)
                        alive = await native_call(item.terminal.alive)
                    else:
                        assert item.process is not None
                        alive = await native_call(item.process.alive)
                    if not alive:
                        item.snapshot.status = "exited"
                        break
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            item.snapshot.status = "closed"
        except Exception:
            item.snapshot.status = "failed"
            item.snapshot.message = (
                "Native transport failed. Close the owned session and review Setup."
            )
        finally:
            await _drain(asyncio.create_task(self._dispose(item)))

    async def _dispose(self, item: OwnedNative) -> None:
        async with item.lock:
            if item.released:
                return
            try:
                if item.terminal:
                    await native_call(item.terminal.close)
                if item.process:
                    await native_call(item.process.close)
            except BaseException:
                item.snapshot.status = "failed"
                raise
            else:
                try:
                    await self._audit(item, item.snapshot.status)
                finally:
                    await item.lease.release()
                    item.released = True

    async def stop(self, handle: NativeHandle) -> NativeSnapshot:
        item = self._get(handle)
        if item.monitor is not None and not item.monitor.done():
            item.monitor.cancel()
            try:
                await _drain(item.monitor)
            except asyncio.CancelledError:
                if not item.monitor.cancelled():
                    raise
        if not item.released:
            item.snapshot.status = "closed"
            await _drain(asyncio.create_task(self._dispose(item)))
        return item.snapshot.model_copy()

    async def close(self) -> None:
        async with self._lock:
            self._closed = True
            errors = []
            for item in self.owned.values():
                try:
                    await self.stop(item.snapshot)
                except Exception as error:
                    errors.append(error)
            if errors:
                raise ExceptionGroup("Native cleanup failed", errors)

    async def record_console(self, data: NativeLaunch) -> None:
        tool = next((tool for tool in load_registry() if tool.id == data.tool_id), None)
        if tool is None or not tool.console or data.mode != "gui":
            raise ValueError("Registered web console required")
        async with await self.workspaces.lease(data.workspace_id) as lease:
            async with lease.sessions.begin() as session:
                session.add(
                    SecDeskAudit(
                        id=str(uuid4()),
                        tool_id=tool.id,
                        mode="gui",
                        event="console-request",
                        authorized=data.authorized,
                        created_at=datetime.now(UTC),
                    )
                )
        await self.hub.publish(
            "secdesk",
            {"tool_id": tool.id, "event": "console-request"},
            workspace_id=data.workspace_id,
        )
