"""Official SDK v2 stdio adapter; local static reads, two owned workers, no listeners."""

import asyncio
import json
from pathlib import Path
from threading import Event
from typing import Literal

from mcp.server import MCPServer
from mcp_types import CallToolResult, TextContent, ToolAnnotations

from shared.lowrea import LowreaOptions
from shared.version import VERSION
from toolkit.lowrea.files import inspect_path
from toolkit.task_context import TaskContext


def create_server() -> MCPServer:
    server = MCPServer("LowREA", version=VERSION, log_level="WARNING")
    slots = asyncio.Semaphore(2)
    pending = 0

    @server.tool(
        annotations=ToolAnnotations(
            read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
        )
    )
    async def inspect_static(
        path: str,
        architecture: Literal["auto", "x86", "x86-64", "arm64"] = "auto",
        offset: int | None = None,
        length: int = 256,
        endian: Literal["little", "big"] = "little",
        base_address: int = 0,
        expected_sha256: str | None = None,
    ) -> CallToolResult:
        """Inspect a named regular file's identity, minimal headers and instruction window.

        Source code, reachability, full xrefs and runtime behavior remain unknown.
        Addresses are preferred image addresses or caller-declared raw decode addresses.
        """
        nonlocal pending
        if pending >= 34:
            value = {
                "isError": True,
                "error": {
                    "code": "capacity_reached",
                    "reason": "Two active and 32 queued inspections are the local capacity. "
                    "Retry later.",
                },
            }
            return CallToolResult(
                is_error=True,
                content=[TextContent(type="text", text=json.dumps(value))],
                structured_content=value,
            )
        pending += 1
        try:
            options = LowreaOptions(
                architecture=architecture,
                offset=offset,
                length=length,
                endian=endian,
                base_address=base_address,
                expected_sha256=expected_sha256,
            )
            async with slots:
                event = Event()
                worker = asyncio.create_task(
                    asyncio.to_thread(inspect_path, Path(path), options, TaskContext(event))
                )
                try:
                    evidence = await asyncio.shield(worker)
                except asyncio.CancelledError:
                    event.set()
                    while not worker.done():
                        try:
                            await asyncio.shield(worker)
                        except asyncio.CancelledError:
                            continue
                        except Exception:
                            break
                    if not worker.cancelled():
                        worker.exception()
                    raise
            value = {"isError": False, "evidence": evidence.record()}
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(value))], structured_content=value
            )
        except (OSError, ValueError):
            value = {
                "isError": True,
                "error": {
                    "code": "artifact_unreadable_or_invalid",
                    "reason": "Supply a regular file within 25 MiB and valid inspection options; "
                    "retry after writes stop.",
                },
            }
            return CallToolResult(
                is_error=True,
                content=[TextContent(type="text", text=json.dumps(value))],
                structured_content=value,
            )
        finally:
            pending -= 1

    return server


def main() -> None:
    create_server().run(transport="stdio")
