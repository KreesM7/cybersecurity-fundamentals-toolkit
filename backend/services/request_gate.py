"""Shared global HTTP pacing independent of any optional analysis module."""

import asyncio
import time


class RequestGate:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.next_at = 0.0

    async def wait(self) -> None:
        async with self.lock:
            await asyncio.sleep(max(0, self.next_at - time.monotonic()))
            self.next_at = time.monotonic() + 1
