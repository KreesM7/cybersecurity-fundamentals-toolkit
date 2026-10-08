"""RAM upload to separate saved-capture worker with bounded streaming and cleanup."""

import asyncio
import time
from contextlib import suppress
from uuid import uuid4

from backend.jobs import JobContext
from backend.platform_utils import (
    capture_worker_argv,
    hidden_process_options,
    is_windows,
    run_process,
)
from shared.capture import MAX_LINE, CaptureProtocol
from toolkit.traffic import MAX_FILE_BYTES, TrafficData

SETUP = "CSV/log ready. Install the separate capture worker for PCAP. See docs/SCAPY_WORKER.md."
_cached: tuple[float, tuple[str, ...], str] | None = None


async def readiness() -> str:
    global _cached
    try:
        command = capture_worker_argv(["--check"])
    except ValueError:
        return SETUP
    key = tuple(command)
    if _cached and _cached[1] == key and time.monotonic() - _cached[0] < 30:
        return _cached[2]
    try:
        reply = await run_process(command, timeout=5, max_output_bytes=65536)
        expected = (
            b'{"worker":"toolkit-scapy-worker","version":"1.0.0","protocol":1,"scapy":"2.8.0"}'
        )
        reason = (
            "CSV/log and saved captures ready."
            if reply.returncode == 0 and reply.stdout.strip() == expected
            else SETUP
        )
    except (OSError, ValueError, RuntimeError, TimeoutError):
        reason = SETUP
    _cached = (time.monotonic(), key, reason)
    return reason


async def read_capture(content: bytes, context: JobContext, *, timeout: float = 60) -> TrafficData:
    context.check()
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("Input exceeds the 25 MiB capture limit.")
    if not 0 < timeout <= 60:
        raise ValueError("Capture timeout must be in (0, 60].")
    token = uuid4().hex
    command = capture_worker_argv(["--control-token", token])
    try:
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=MAX_LINE,
                **hidden_process_options(),
            )
        )
        try:
            process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            context.cancel_event.set()
            while not spawn.done():
                try:
                    await asyncio.shield(spawn)
                except asyncio.CancelledError:
                    continue
            process = spawn.result()
    except OSError:
        context.check()
        raise ValueError(SETUP) from None
    parser = CaptureProtocol()

    async def upload() -> None:
        assert process.stdin is not None
        try:
            for offset in range(0, len(content), 65536):
                context.check()
                process.stdin.write(content[offset : offset + 65536])
                await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            process.stdin.close()
            with suppress(BrokenPipeError, ConnectionResetError):
                await process.stdin.wait_closed()

    async def output() -> None:
        assert process.stdout is not None
        while line := await process.stdout.readline():
            context.check()
            parser.feed(line)

    async def stderr() -> None:
        assert process.stderr is not None
        used = 0
        while chunk := await process.stderr.read(65536):
            used += len(chunk)
            if used > 65536:
                raise ValueError("Capture worker stderr limit exceeded.")

    tasks = [asyncio.create_task(function()) for function in (upload, output, stderr)]

    async def cleanup() -> None:
        for task in tasks:
            task.cancel()
        if process.stdin is not None and not process.stdin.is_closing():
            process.stdin.transport.abort()
        await asyncio.gather(*tasks, return_exceptions=True)

        async def discard(stream: asyncio.StreamReader | None) -> None:
            if stream is not None:
                while await stream.read(65536):
                    pass

        # Reap requires draining pipe transports even after a parser/limit/cancel failure.
        drains = [
            asyncio.create_task(discard(stream)) for stream in (process.stdout, process.stderr)
        ]
        if process.returncode is None:
            if is_windows():
                # Fixed distro and random capability target just this worker's private socket.
                with suppress(OSError, ValueError, RuntimeError, TimeoutError):
                    await run_process(
                        capture_worker_argv(["--cancel-token", token]),
                        timeout=7,
                        max_output_bytes=65536,
                    )
                # Worker enforces its own 60-second alarm, including stdin upload.
                await process.wait()
            else:
                with suppress(ProcessLookupError):
                    process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), 2)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        process.kill()
                    await process.wait()
        await asyncio.gather(*drains)

    try:
        context.check()
        async with asyncio.timeout(timeout):
            await asyncio.gather(*tasks)
            await process.wait()
    except (ValueError, TimeoutError):
        parser.invalid = True
    finally:
        owned_cleanup = asyncio.create_task(cleanup())
        while not owned_cleanup.done():
            try:
                await asyncio.shield(owned_cleanup)
            except asyncio.CancelledError:
                context.cancel_event.set()
        owned_cleanup.result()
    context.check()
    data = parser.finish(process.returncode if process.returncode is not None else 1)
    if not data.events and not data.complete:
        raise ValueError("Capture analysis failed or incomplete. " + "; ".join(data.warnings[:3]))
    return data
