"""Per-instance bearer authentication shared by REST and WebSocket handshakes."""

from __future__ import annotations

import re
import secrets
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import JSONResponse
from starlette.responses import Response

TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def valid_bearer(header: str | None, token: str) -> bool:
    """Accept exactly one ASCII bearer token; query parameters are never consulted."""
    if header is None:
        return False
    pieces = header.split(" ")
    if len(pieces) != 2 or pieces[0].lower() != "bearer":
        return False
    candidate = pieces[1]
    return bool(TOKEN_PATTERN.fullmatch(candidate)) and secrets.compare_digest(candidate, token)


def install_auth(app: FastAPI, token: str, *, allowed_origins: set[str]) -> None:
    """Require a fresh instance token and exact origin on every HTTP request."""
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("Instance token must contain 256 random bits encoded as lowercase hex.")
    app.state.allowed_origins = frozenset(allowed_origins)

    @app.middleware("http")
    async def authorize(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        origin = request.headers.get("origin")
        if origin is not None and origin not in allowed_origins:
            return JSONResponse({"detail": "Origin is not allowed."}, status_code=403)
        if not valid_bearer(request.headers.get("authorization"), token):
            return JSONResponse(
                {"detail": "Instance authentication required."},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
        return response


async def authenticate_websocket(
    websocket: WebSocket, token: str, allowed_origins: set[str]
) -> bool:
    """Reject untrusted WS peers before accepting, without exposing the token."""
    origin = websocket.headers.get("origin")
    if (origin is not None and origin not in allowed_origins) or not valid_bearer(
        websocket.headers.get("authorization"), token
    ):
        await websocket.close(code=1008, reason="Instance authentication required.")
        return False
    return True
