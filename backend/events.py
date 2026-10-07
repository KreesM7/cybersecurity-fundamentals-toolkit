"""Bounded workspace-scoped event fanout with an explicit resynchronization path."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from pydantic import JsonValue

from backend.redaction import Redactor
from shared.schemas import SchemaModel


class SlowConsumerError(RuntimeError):
    """The consumer must reconnect and reload its REST snapshot."""


class EventMessage(SchemaModel):
    """Monotonic event envelope; reconnect clients obtain fresh state through REST."""

    sequence: int
    topic: str
    workspace_id: UUID | None
    timestamp: datetime
    data: JsonValue


@dataclass(eq=False)
class Subscription:
    topic: str
    workspace_id: UUID | None
    queue: asyncio.Queue[EventMessage]
    closed: asyncio.Event

    async def receive(self) -> EventMessage:
        if self.closed.is_set():
            raise SlowConsumerError("Event queue overflowed or closed; reload REST state.")
        get = asyncio.create_task(self.queue.get())
        closed = asyncio.create_task(self.closed.wait())
        try:
            done, _ = await asyncio.wait((get, closed), return_when=asyncio.FIRST_COMPLETED)
            if closed in done or self.closed.is_set():
                raise SlowConsumerError("Event queue overflowed or closed; reload REST state.")
            return get.result()
        finally:
            for task in (get, closed):
                if not task.done():
                    task.cancel()
            await asyncio.gather(get, closed, return_exceptions=True)


class EventHub:
    """Publishing never waits on a subscriber; a full queue disconnects that peer."""

    def __init__(self, queue_size: int = 256) -> None:
        if not 1 <= queue_size <= 256:
            raise ValueError("Subscriber queue must contain 1 to 256 events.")
        self.queue_size = queue_size
        self._sequence = 0
        self._subscriptions: set[Subscription] = set()
        self.recent: deque[EventMessage] = deque(maxlen=100)
        self.redactor = Redactor()

    def subscribe(self, topic: str, workspace_id: UUID | None = None) -> Subscription:
        if len(self._subscriptions) >= 128:
            raise SlowConsumerError(
                "Subscriber capacity reached; try again after closing a connection."
            )
        subscription = Subscription(
            topic, workspace_id, asyncio.Queue(self.queue_size), asyncio.Event()
        )
        self._subscriptions.add(subscription)
        return subscription

    def unsubscribe(self, subscription: Subscription) -> None:
        self._subscriptions.discard(subscription)
        subscription.closed.set()

    async def publish(
        self, topic: str, data: JsonValue, *, workspace_id: UUID | None = None
    ) -> None:
        safe_data = self.redactor.clean(data)
        if len(json.dumps(safe_data, allow_nan=False).encode("utf-8")) > 60000:
            safe_data = {
                "message": "Event exceeded its size limit; reload REST state.",
                "resync": True,
            }
        self._sequence += 1
        message = EventMessage(
            sequence=self._sequence,
            topic=topic,
            workspace_id=workspace_id,
            timestamp=datetime.now(UTC),
            data=safe_data,
        )
        self.recent.append(message)
        for subscriber in tuple(self._subscriptions):
            if subscriber.topic not in (topic, "events"):
                continue
            if subscriber.workspace_id is not None and subscriber.workspace_id != workspace_id:
                continue
            try:
                subscriber.queue.put_nowait(message)
            except asyncio.QueueFull:
                self.unsubscribe(subscriber)

    async def close(self) -> None:
        for subscriber in tuple(self._subscriptions):
            self.unsubscribe(subscriber)
        self.redactor.clear()
