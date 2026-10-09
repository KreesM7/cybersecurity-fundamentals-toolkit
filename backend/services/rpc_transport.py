"""Serialized, verified HTTPS transport using the SDK's MessagePack codec only."""

from __future__ import annotations

import asyncio
import importlib
import ipaddress
import ssl
from collections.abc import Callable
from typing import Protocol, cast
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import JsonValue, TypeAdapter

_json: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)
MAX_RESPONSE = 4 * 1024 * 1024


def _text_values(value: object, depth: int = 0) -> object:
    """Ruby's binary-encoded strings arrive as MessagePack bytes, including map keys."""
    if depth > 64:
        raise ValueError("Response nesting limit")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, list):
        return [_text_values(item, depth + 1) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            normalized = _text_values(key, depth + 1)
            if not isinstance(normalized, (str, int)) or isinstance(normalized, bool):
                raise ValueError("Unsupported map key")
            key_text = str(normalized)
            if key_text in result:
                raise ValueError("Ambiguous map key")
            result[key_text] = _text_values(item, depth + 1)
        return result
    return value


class RpcFailureError(RuntimeError):
    """A sanitized remote failure; mutations may already have executed."""


RpcFailure = RpcFailureError


class FrameworkTransport(Protocol):
    identity: str | None

    async def call(
        self, method: str, args: list[JsonValue] | None = None
    ) -> dict[str, JsonValue]: ...

    async def close(self) -> None: ...


class RpcTransport:
    """Never invokes the SDK's insecure HTTP client or permanent-token login."""

    def __init__(
        self,
        url: str,
        context: ssl.SSLContext,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        deadline: float = 15.0,
    ) -> None:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or not parsed.hostname
            or not parsed.port
            or parsed.path != "/api/"
        ):
            raise ValueError("RPC requires an HTTPS literal IP, explicit port and /api/ path.")
        address = ipaddress.ip_address(parsed.hostname)
        if address.is_unspecified or address.is_multicast or "%" in parsed.hostname:
            raise ValueError("RPC requires a unicast literal address.")
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("RPC certificate and hostname verification must remain enabled.")
        if not 0 < deadline <= 30:
            raise ValueError("RPC deadline must be between zero and thirty seconds.")
        self.url, self.deadline = url, deadline
        self.token: str | None = None
        self.identity: str | None = None
        self._lock = asyncio.Lock()
        self._pending = 0
        self._closed = False
        self._client = httpx.AsyncClient(
            verify=context,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(10, connect=3),
            limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
            transport=transport,
        )

    async def login(self, username: str, password: str) -> str:
        if not username or len(username) > 200 or not password or len(password) > 4096:
            raise ValueError("RPC credentials are empty or too long.")
        reply = await self.call("auth.login", [username, password])
        token = reply.get("token")
        if (
            reply.get("result") != "success"
            or not isinstance(token, str)
            or not token.startswith("TEMP")
        ):
            raise RpcFailure("RPC temporary-token authentication failed.")
        if len(token) > 256:
            raise RpcFailure("RPC authentication response is invalid.")
        self.token = token
        try:
            identity = await self.call("toolkit.identity")
            value = identity.get("id")
            if not isinstance(value, str):
                raise ValueError("Missing identity")
            self.identity = str(UUID(value))
        except (ValueError, RpcFailure) as exc:
            await self.close()
            raise RpcFailure(
                "Install the Toolkit RPC startup bridge to identify this instance."
            ) from exc
        return self.identity

    async def call(self, method: str, args: list[JsonValue] | None = None) -> dict[str, JsonValue]:
        if self._closed:
            raise RpcFailure("RPC connection is closed.")
        if self._pending >= 32:
            raise RpcFailure("RPC queue is full; wait for outstanding operations.")
        self._pending += 1
        try:
            async with asyncio.timeout(self.deadline):
                async with self._lock:
                    if self._closed:
                        raise RpcFailure("RPC connection is closed.")
                    return await self._exchange(method, args or [])
        except (httpx.HTTPError, TimeoutError) as exc:
            raise RpcFailure(
                "RPC connection failed or timed out; execution may be uncertain."
            ) from exc
        finally:
            self._pending -= 1

    async def _exchange(self, method: str, args: list[JsonValue]) -> dict[str, JsonValue]:
        try:
            codec = importlib.import_module("pymetasploit3.utils")
        except ImportError as exc:
            raise RpcFailure("Install the pinned pymetasploit3 dependency to connect.") from exc
        encode = cast(Callable[[object], bytes], codec.encode)
        decode = cast(Callable[[bytes], object], codec.decode)
        if method != "auth.login" and self.token is None:
            raise RpcFailure("RPC is not authenticated.")
        envelope: list[JsonValue] = [method]
        if method != "auth.login":
            envelope.append(self.token)
        envelope.extend(args)
        payload = encode(envelope)
        if len(payload) > 1024 * 1024:
            raise ValueError("RPC request exceeds one MiB.")
        body = bytearray()
        async with self._client.stream(
            "POST", self.url, content=payload, headers={"Content-Type": "binary/message-pack"}
        ) as response:
            if response.status_code != 200:
                raise RpcFailure("RPC rejected the request; verify credentials and server setup.")
            async for chunk in response.aiter_bytes(65536):
                if len(body) + len(chunk) > MAX_RESPONSE:
                    raise RpcFailure("RPC response exceeded the four MiB limit.")
                body.extend(chunk)
        try:
            value = _json.validate_python(_text_values(decode(bytes(body))))
            if method == "module.search" and isinstance(value, list):
                value = {"modules": value}
            if method == "module.encode_formats" and isinstance(value, list):
                value = {"formats": value}
            if not isinstance(value, dict):
                raise ValueError("Expected response object")
        except Exception as exc:
            raise RpcFailure("RPC returned an invalid MessagePack response.") from exc
        if value.get("error"):
            raise RpcFailure("Framework rejected the operation. Check its required options.")
        return value

    async def close(self) -> None:
        if self._closed:
            return
        async with self._lock:
            self._closed = True
            token = self.token
            try:
                if token:
                    async with asyncio.timeout(3):
                        await self._exchange("auth.logout", [token])
            except (RpcFailure, httpx.HTTPError, TimeoutError):
                pass
            finally:
                self.token = None
                self.identity = None
                await self._client.aclose()
