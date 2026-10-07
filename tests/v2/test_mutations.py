from __future__ import annotations

import asyncio
import unittest
from uuid import uuid4

from backend.mutations import (
    MemoryMutationStore,
    MutationConflictError,
    MutationCoordinator,
    UnknownOutcomeError,
)


class MutationTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicates_are_serialized_and_conflicting_payload_rejected(self) -> None:
        store = MemoryMutationStore()
        coordinator = MutationCoordinator(store)
        workspace, request = uuid4(), uuid4()
        calls = 0

        async def action() -> dict[str, int]:
            nonlocal calls
            calls += 1
            await asyncio.sleep(0.01)
            return {"calls": calls}

        first, second = await asyncio.gather(
            coordinator.execute(workspace, request, "run", {"target": "127.0.0.1"}, action),
            coordinator.execute(workspace, request, "run", {"target": "127.0.0.1"}, action),
        )
        self.assertEqual(first, second)
        self.assertEqual(calls, 1)
        with self.assertRaises(MutationConflictError):
            await coordinator.execute(workspace, request, "run", {"target": "127.0.0.2"}, action)

    async def test_unknown_outcome_after_failure_or_restart_is_never_repeated(self) -> None:
        store = MemoryMutationStore()
        coordinator = MutationCoordinator(store)
        workspace, request = uuid4(), uuid4()
        calls = 0

        async def external_command() -> None:
            nonlocal calls
            calls += 1
            raise TimeoutError("Transport lost after command was sent")

        with self.assertRaises(TimeoutError):
            await coordinator.execute(workspace, request, "run", {}, external_command)
        with self.assertRaises(UnknownOutcomeError):
            await MutationCoordinator(store).execute(
                workspace, request, "run", {}, external_command
            )
        self.assertEqual(calls, 1)

    async def test_secret_mutations_do_not_persist_inputs_or_results(self) -> None:
        store = MemoryMutationStore()
        coordinator = MutationCoordinator(store)
        workspace, request = uuid4(), uuid4()

        async def analyze() -> dict[str, str]:
            return {"analysis": "memory-only"}

        result = await coordinator.execute(
            workspace, request, "password", {"password": "sentinel-secret"}, analyze, secret=True
        )
        self.assertEqual(result, {"analysis": "memory-only"})
        self.assertFalse(store.records)
        with self.assertRaises(MutationConflictError):
            await coordinator.execute(
                workspace, request, "password", {"password": "different"}, analyze, secret=True
            )
        with self.assertRaises(MutationConflictError):
            await coordinator.execute(workspace, request, "ordinary-command", {}, analyze)


if __name__ == "__main__":
    unittest.main()
