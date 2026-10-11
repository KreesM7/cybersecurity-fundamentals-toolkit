"""Shared HTTP-body and WebSocket-message limits for every application router."""

import asyncio
import time
from collections import deque

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send
from starlette.websockets import WebSocketDisconnect

WS_MAX_MESSAGE_BYTES = 65536
WS_MESSAGES_PER_SECOND = 100


class WebSocketLimits:
    """Apply size and sliding-window rate bounds in both directions, before route handlers."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "websocket":
            await self.app(scope, receive, send)
            return
        incoming: deque[float] = deque()
        outgoing: deque[float] = deque()
        closed = False

        async def reject(code: int) -> None:
            nonlocal closed
            if not closed:
                closed = True
                try:
                    async with asyncio.timeout(1):
                        await send(
                            {
                                "type": "websocket.close",
                                "code": code,
                                "reason": "Stream limit exceeded; reload REST state.",
                            }
                        )
                except (TimeoutError, RuntimeError, WebSocketDisconnect):
                    pass
            raise WebSocketDisconnect(code)

        async def check(message: Message, window: deque[float]) -> None:
            if closed:
                raise WebSocketDisconnect(1000)
            size = len(message.get("bytes") or b"") + len(
                (message.get("text") or "").encode("utf-8")
            )
            if size > WS_MAX_MESSAGE_BYTES:
                await reject(1009)
            now = time.monotonic()
            while window and window[0] <= now - 1:
                window.popleft()
            if len(window) >= WS_MESSAGES_PER_SECOND:
                await reject(1013)
            window.append(now)

        async def bounded_receive() -> Message:
            message = await receive()
            if message["type"] == "websocket.receive":
                await check(message, incoming)
            return message

        async def bounded_send(message: Message) -> None:
            nonlocal closed
            if message["type"] == "websocket.send":
                await check(message, outgoing)
            elif message["type"] == "websocket.close":
                if closed:
                    raise WebSocketDisconnect(1000)
                closed = True
            await send(message)

        try:
            await self.app(scope, bounded_receive, bounded_send)
        except WebSocketDisconnect:
            pass


class RequestBodyLimit:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        multipart = headers.get(b"content-type", b"").lower().startswith(b"multipart/form-data;")
        limit = 26 * 1024 * 1024 if multipart else 1024 * 1024
        messages: list[Message] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > limit:
                response = JSONResponse({"detail": "Request body exceeds its limit."}, 413)
                await response(scope, receive, send)
                return
            messages.append(message)
            if not message.get("more_body", False):
                break
        cursor = iter(messages)

        async def bounded_receive() -> Message:
            return next(cursor, {"type": "http.request", "body": b"", "more_body": False})

        await self.app(scope, bounded_receive, send)
