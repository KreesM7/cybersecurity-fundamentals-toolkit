"""Bound authenticated request bodies before parsers allocate upload buffers."""

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


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
