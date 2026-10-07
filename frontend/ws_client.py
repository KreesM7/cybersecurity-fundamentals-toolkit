"""Authenticated WSS streams with caller-supplied trust and no environment proxies."""

import ssl
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from websockets.asyncio.client import connect
from websockets.exceptions import InvalidStatus

from frontend.api_client import validate_connection


class WebSocketRedirectError(RuntimeError):
    """A local backend attempted to move its authenticated websocket connection."""


class _NoRedirectConnect(connect):
    """Refuse redirect responses at the hook before websockets opens another connection."""

    def process_redirect(self, exc: Exception) -> Exception:
        if isinstance(exc, InvalidStatus) and 300 <= exc.response.status_code < 400:
            return WebSocketRedirectError(
                "Backend websocket redirects are refused. "
                "Reconnect using the authenticated instance locator."
            )
        return exc


class WebSocketClient:
    """Consume secure instance streams; cancellation closes the connection."""

    def __init__(self, base_url: str, ssl_context: ssl.SSLContext, instance_token: str) -> None:
        validate_connection(base_url, ssl_context, instance_token)
        self._base_url = urlsplit(base_url.rstrip("/"))._replace(scheme="wss").geturl()
        self._context = ssl_context
        self._token = instance_token

    async def messages(self, path: str) -> AsyncIterator[str | bytes]:
        """Yield bounded messages until disconnect, with no automatic retry."""
        if (
            not path.startswith(("/api/v1/", "/ws/"))
            or urlsplit(path).netloc
            or "\\" in path
            or "#" in path
            or "/../" in path
        ):
            raise ValueError("Expected a local /ws/ stream")
        async with _NoRedirectConnect(
            self._base_url + path,
            ssl=self._context,
            additional_headers={"Authorization": f"Bearer {self._token}"},
            proxy=None,
            max_size=1048576,
            max_queue=16,
            open_timeout=5,
            close_timeout=2,
        ) as connection:
            async for message in connection:
                yield message
