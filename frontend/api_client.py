"""Async typed HTTPS boundary; views never perform HTTP requests directly."""

import re
import ssl
from collections.abc import Mapping
from types import TracebackType
from typing import Self, TypeVar
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx

from shared.schemas import HealthResponse, SchemaModel

Model = TypeVar("Model", bound=SchemaModel)


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
        response = await self._client.request(
            method,
            path,
            json=body.model_dump(mode="json") if body is not None else None,
            headers=request_headers,
        )
        response.raise_for_status()
        return response_type.model_validate_json(response.content)

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
