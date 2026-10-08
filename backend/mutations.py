"""Stable mutation IDs prevent replay when an external command's outcome is uncertain."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from uuid import UUID

from pydantic import BaseModel, JsonValue, TypeAdapter

_json: TypeAdapter[JsonValue] = TypeAdapter(JsonValue)


class MutationConflictError(ValueError):
    """The same request ID was used with a different operation or payload."""


class UnknownOutcomeError(RuntimeError):
    """The command may have run; explicit reconciliation is required before a new ID."""


class MutationCapacityError(RuntimeError):
    """Memory-only replay tracking reached its bound; no tracked request was evicted."""


@dataclass(frozen=True)
class MutationRecord:
    workspace_id: UUID
    request_id: UUID
    operation: str
    fingerprint: str
    state: Literal["pending", "complete", "unknown"]
    result: JsonValue = None


class MutationStore(Protocol):
    async def get(self, workspace_id: UUID, request_id: UUID) -> MutationRecord | None: ...

    async def reserve(self, record: MutationRecord) -> bool: ...

    async def finish(self, record: MutationRecord) -> None: ...


class MemoryMutationStore:
    """Bounded ephemeral store for tests and secret-bearing mutation envelopes."""

    def __init__(self, limit: int = 10000) -> None:
        self.limit = limit
        self.records: dict[tuple[UUID, UUID], MutationRecord] = {}

    async def get(self, workspace_id: UUID, request_id: UUID) -> MutationRecord | None:
        return self.records.get((workspace_id, request_id))

    async def reserve(self, record: MutationRecord) -> bool:
        key = (record.workspace_id, record.request_id)
        if key in self.records:
            return False
        if len(self.records) >= self.limit:
            raise MutationCapacityError(
                "Replay tracking is full. Restart after reconciling active operations."
            )
        self.records[key] = record
        return True

    async def finish(self, record: MutationRecord) -> None:
        key = (record.workspace_id, record.request_id)
        current = self.records[key]
        if current.fingerprint != record.fingerprint or current.operation != record.operation:
            raise MutationConflictError("Mutation identity changed while completing the operation.")
        self.records[key] = record


class MutationCoordinator:
    """Reserve before executing; completion never stores request bodies or exception text."""

    def __init__(self, store: MutationStore, *, profile: Path | None = None) -> None:
        self.store = store
        self._secrets = MemoryMutationStore()
        self._fingerprint_key = secrets.token_bytes(32)
        self._locks: dict[tuple[UUID, UUID], asyncio.Lock] = {}
        self._durable_key: bytes | None = None
        if profile is not None:
            from backend.platform_utils import assert_private_path, atomic_private_write

            key_path = profile / "mutation.key"
            if not key_path.exists():
                atomic_private_write(key_path, secrets.token_bytes(32))
            assert_private_path(key_path)
            key = key_path.read_bytes()
            if len(key) != 32:
                raise ValueError("Mutation key is invalid; restore the profile backup.")
            self._durable_key = key

    async def execute_external(
        self,
        workspace_id: UUID,
        request_id: UUID,
        operation: str,
        payload: JsonValue,
        action: Callable[[], Awaitable[object]],
    ) -> JsonValue:
        """Persist a keyed identity before dispatch; action returns only safe outcome metadata."""
        if self._durable_key is None:
            raise RuntimeError("External mutations require a protected profile key.")
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        fingerprint = hmac.new(self._durable_key, canonical.encode(), hashlib.sha256).hexdigest()
        return await self.execute(
            workspace_id, request_id, "external:" + operation, fingerprint, action
        )

    async def execute(
        self,
        workspace_id: UUID,
        request_id: UUID,
        operation: str,
        payload: JsonValue,
        action: Callable[[], Awaitable[object]],
        *,
        secret: bool = False,
    ) -> JsonValue:
        if not operation or len(operation) > 200:
            raise ValueError("Invalid mutation operation.")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
        fingerprint = (
            hmac.new(self._fingerprint_key, canonical, hashlib.sha256).hexdigest()
            if secret
            else hashlib.sha256(canonical).hexdigest()
        )
        key = (workspace_id, request_id)
        if key not in self._locks:
            if len(self._locks) >= 10000:
                raise MutationCapacityError(
                    "Mutation tracking capacity reached. Reconcile before restarting."
                )
            self._locks[key] = asyncio.Lock()
        store: MutationStore = self._secrets if secret else self.store
        async with self._locks[key]:
            other_store: MutationStore = self.store if secret else self._secrets
            if await other_store.get(*key) is not None:
                raise MutationConflictError(
                    "Request ID was already used for another mutation class."
                )
            prior = await store.get(*key)
            if prior is not None:
                return self._prior_result(prior, operation, fingerprint)
            record = MutationRecord(workspace_id, request_id, operation, fingerprint, "pending")
            if not await store.reserve(record):
                prior = await store.get(*key)
                assert prior is not None
                return self._prior_result(prior, operation, fingerprint)
            try:
                value = await action()
                if isinstance(value, BaseModel):
                    value = value.model_dump(mode="json")
                result = _json.validate_python(value)
                await store.finish(
                    MutationRecord(
                        workspace_id, request_id, operation, fingerprint, "complete", result
                    )
                )
                return result
            except BaseException:
                # Even cancellation can occur after dispatch. A later duplicate must not run again.
                await asyncio.shield(
                    store.finish(
                        MutationRecord(workspace_id, request_id, operation, fingerprint, "unknown")
                    )
                )
                raise

    @staticmethod
    def _prior_result(prior: MutationRecord, operation: str, fingerprint: str) -> JsonValue:
        if prior.operation != operation or not secrets.compare_digest(
            prior.fingerprint, fingerprint
        ):
            raise MutationConflictError("Request ID was already used for a different mutation.")
        if prior.state != "complete":
            raise UnknownOutcomeError(
                "Previous execution outcome is unknown. Inspect state before any new request."
            )
        return prior.result
