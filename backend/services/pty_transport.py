"""Bounded JSONL client for the independently supervised Metasploit PTY host."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Sequence
from contextlib import suppress
from uuid import UUID, uuid4

from pydantic import JsonValue, TypeAdapter

from backend.platform_utils import hidden_process_options, run_process
from backend.services.rpc_transport import RpcFailure

_json: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
LIMIT = 4 * 1024 * 1024


class PtyTransport:
    def __init__(
        self,
        argv: Sequence[str],
        output: Callable[[str], None],
        *,
        cancel_argv: Sequence[str] | None = None,
    ) -> None:
        self.argv, self.output, self.cancel_argv = argv, output, cancel_argv
        self.identity: str | None = None
        self.process: asyncio.subprocess.Process | None = None
        self.failed = False
        self._lock = asyncio.Lock()
        self._stderr: asyncio.Task[None] | None = None
        self._pending = 0

    async def start(self) -> None:
        self.process = await asyncio.create_subprocess_exec(
            *self.argv,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=LIMIT + 1,
            **hidden_process_options(),
        )
        self._stderr = asyncio.create_task(self._drain_stderr())
        try:
            async with asyncio.timeout(60):
                total = 0
                while True:
                    record = await self._record()
                    if record.get("type") != "output":
                        break
                    text = record.get("text")
                    if not isinstance(text, str):
                        raise ValueError("Invalid startup output")
                    total += len(text.encode())
                    if total > LIMIT:
                        raise ValueError("Startup output limit")
                    self.output(text[:10000])
                if record.get("type") != "ready" or not str(record.get("version", "")).startswith(
                    "6."
                ):
                    raise ValueError("Incompatible framework")
                self.identity = str(UUID(str(record.get("id"))))
        except BaseException:
            await self.close()
            raise

    async def _drain_stderr(self) -> None:
        assert self.process and self.process.stderr
        total = 0
        while block := await self.process.stderr.read(8192):
            total += len(block)
            if total > 65536:
                self.failed = True
                return

    async def _record(self) -> dict[str, JsonValue]:
        assert self.process and self.process.stdout
        line = await self.process.stdout.readline()
        if not line or len(line) > LIMIT or not line.endswith(b"\n"):
            raise ValueError("Missing or oversized frame")
        value = _json.validate_json(line)
        if not isinstance(value, dict) or type(value.get("v")) is not int or value.get("v") != 1:
            raise ValueError("Invalid frame version")
        return value

    async def call(self, method: str, args: list[JsonValue] | None = None) -> dict[str, JsonValue]:
        if self.failed or self.process is None or self.process.returncode is not None:
            raise RpcFailure("PTY bridge unavailable; previous execution may be uncertain.")
        if self._pending >= 32:
            raise RpcFailure("Framework queue is full.")
        self._pending += 1
        try:
            async with asyncio.timeout(20):
                async with self._lock:
                    if self.failed:
                        raise RpcFailure(
                            "PTY bridge unavailable; previous execution may be uncertain."
                        )
                    identifier = str(uuid4())
                    request = (
                        json.dumps(
                            {"v": 1, "id": identifier, "method": method, "args": args or []}
                        ).encode()
                        + b"\n"
                    )
                    if len(request) > 1024 * 1024:
                        raise ValueError("Framework command exceeds one MiB.")
                    assert self.process.stdin
                    self.process.stdin.write(request)
                    await self.process.stdin.drain()
                    total = 0
                    while True:
                        record = await self._record()
                        if self.failed:
                            raise ValueError("Diagnostic output limit")
                        if record.get("type") == "output":
                            value = record.get("text")
                            if not isinstance(value, str):
                                raise ValueError("Invalid output frame")
                            total += len(value.encode())
                            if total > LIMIT:
                                raise ValueError("Console output limit")
                            self.output(value[:10000])
                            continue
                        if record.get("id") != identifier or record.get("type") not in {
                            "result",
                            "error",
                        }:
                            raise ValueError("Unexpected reply identity")
                        if record["type"] == "error":
                            raise RpcFailure(
                                "Framework rejected the operation; execution may be uncertain."
                            )
                        data = record.get("data")
                        if method == "module.search" and isinstance(data, list):
                            data = {"modules": data}
                        if method == "module.encode_formats" and isinstance(data, list):
                            data = {"formats": data}
                        if not isinstance(data, dict):
                            raise ValueError("Invalid structured reply")
                        return data
        except (ValueError, OSError, TimeoutError, asyncio.CancelledError, RpcFailure) as exc:
            self.failed = True
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RpcFailure(
                "PTY reply failed; execution is uncertain and was not repeated."
            ) from exc
        finally:
            self._pending -= 1

    async def close(self) -> None:
        self.failed = True
        process = self.process
        if process is None:
            return
        if process.returncode is None and self.cancel_argv:
            await run_process(self.cancel_argv, timeout=5, max_output_bytes=65536)
        if process.stdin:
            process.stdin.close()
        if process.returncode is None:
            try:
                await asyncio.wait_for(process.wait(), 10)
            except TimeoutError:
                if self.cancel_argv:
                    raise RpcFailure(
                        "Could not confirm owned PTY shutdown. Check Toolkit-MSF."
                    ) from None
                with suppress(ProcessLookupError):
                    process.kill()
                await process.wait()
        if self._stderr:
            await self._stderr
        self.identity = None
