"""Async typed HTTPS boundary; views never perform HTTP requests directly."""

import re
import ssl
from collections.abc import Mapping
from types import TracebackType
from typing import Self, TypeVar
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
from pydantic import BaseModel

from shared.framework import RpcConnect
from shared.schemas import HealthResponse, SchemaModel
from shared.tools import PasswordOptions

Model = TypeVar("Model", bound=BaseModel)
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


class ApiError(httpx.HTTPStatusError):
    """Actionable backend detail without response/request body or credential retention."""

    def __init__(self, message: str) -> None:
        # Preserve the existing HTTPStatusError contract with sanitized local context.
        # Never retain the actual request, which can contain a password body.
        super().__init__(
            message,
            request=httpx.Request("GET", "https://127.0.0.1/"),
            response=httpx.Response(400),
        )


def validate_connection(base_url: str, ssl_context: ssl.SSLContext, instance_token: str) -> None:
    """Require certificate verification and a token before a connection is created."""
    url = urlsplit(base_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        raise ValueError("A credential-free HTTPS base URL is required")
    if url.hostname != "127.0.0.1" or url.port is None or not 1 <= url.port <= 65535:
        raise ValueError("The backend must use literal 127.0.0.1 with an explicit valid port")
    if url.path not in {"", "/"}:
        raise ValueError("The HTTPS base URL must not contain a resource path")
    if url.query or url.fragment:
        raise ValueError("The HTTPS base URL must not contain a query or fragment")
    if ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname:
        raise ValueError("TLS certificate and hostname verification are required")
    if re.fullmatch(r"[0-9a-f]{64}", instance_token) is None:
        raise ValueError("A valid instance token is required")


class ApiClient:
    """Single-owner HTTPX client; mutations are sent once and never retried."""

    def __init__(
        self,
        base_url: str,
        ssl_context: ssl.SSLContext,
        instance_token: str,
        *,
        transport: httpx.ASGITransport | None = None,
    ) -> None:
        validate_connection(base_url, ssl_context, instance_token)
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            verify=ssl_context,
            headers={"Authorization": f"Bearer {instance_token}"},
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(15.0, connect=5.0),
        )

    async def request(
        self,
        method: str,
        path: str,
        response_type: type[Model],
        body: SchemaModel | None = None,
        *,
        request_id: UUID | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> Model:
        """Request a relative API resource and validate its versioned response."""
        if not path.startswith("/api/v1/") or urlsplit(path).netloc or "\\" in path:
            raise ValueError("Expected a local /api/v1/ resource")
        request_headers = dict(headers or {})
        if any(
            name.lower() in {"authorization", "host", "x-request-id"} for name in request_headers
        ):
            raise ValueError("Authorization, Host and X-Request-ID headers cannot be overridden")
        if method.upper() in {"POST", "PUT", "PATCH", "DELETE"}:
            request_headers["X-Request-ID"] = str(request_id or uuid4())
        payload = (
            body.transport_dump()
            if isinstance(body, (PasswordOptions, RpcConnect))
            else body.model_dump(mode="json") if body is not None else None
        )
        async with self._client.stream(
            method,
            path,
            json=payload,
            headers=request_headers,
            timeout=httpx.Timeout(75 if path == "/api/v1/connection/fallback" else 30, connect=5),
        ) as response:
            content = await self._bounded_response(response)
            if response.status_code == 204:
                return response_type.model_validate({})
            return response_type.model_validate_json(content)

    @staticmethod
    async def _bounded_response(response: httpx.Response) -> bytes:
        chunks, total = [], 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ApiError(
                    "Backend response exceeds the 16 MiB limit. "
                    "Clear the result and use a smaller input."
                )
            chunks.append(chunk)
        content = b"".join(chunks)
        if not response.is_success:
            detail = "Backend action failed. Check fields, readiness and workspace selection."
            try:
                from json import loads

                value = loads(content).get("detail")
                if isinstance(value, str):
                    detail = value[:1000]
            except (ValueError, AttributeError):
                pass
            raise ApiError(detail)
        return content

    async def upload(
        self,
        path: str,
        response_type: type[Model],
        body: SchemaModel,
        content: bytes,
        filename: str,
        *,
        request_id: UUID,
    ) -> Model:
        if not path.startswith("/api/v1/") or urlsplit(path).netloc or "\\" in path:
            raise ValueError("Expected a local /api/v1/ resource")
        if len(content) > MAX_UPLOAD_BYTES:
            raise ApiError("Selected file exceeds the 25 MiB upload limit.")
        from pathlib import PurePosixPath

        basename = PurePosixPath(filename.replace("\\", "/")).name
        async with self._client.stream(
            "POST",
            path,
            headers={"X-Request-ID": str(request_id)},
            data={"options": body.model_dump_json()},
            files={"file": (basename, content, "application/octet-stream")},
        ) as response:
            return response_type.model_validate_json(await self._bounded_response(response))

    async def health(self) -> HealthResponse:
        """Fetch actual backend identity and readiness."""
        return await self.request("GET", "/api/v1/health", HealthResponse)

    async def close(self) -> None:
        """Release connection resources in the owning asyncio loop."""
        await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()
