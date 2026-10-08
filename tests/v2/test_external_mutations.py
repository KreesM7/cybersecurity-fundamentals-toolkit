from uuid import uuid4

import pytest

from backend.mutations import (
    MemoryMutationStore,
    MutationConflictError,
    MutationCoordinator,
    UnknownOutcomeError,
)


@pytest.mark.asyncio
async def test_durable_secret_replay_conflict_and_unknown_after_restart(tmp_path):
    store = MemoryMutationStore()
    scope, completed, unknown = uuid4(), uuid4(), uuid4()
    coordinator = MutationCoordinator(store, profile=tmp_path)
    calls = 0

    async def run():
        nonlocal calls
        calls += 1
        return {"id": "job-1"}

    async def uncertain():
        nonlocal calls
        calls += 1
        raise TimeoutError("private response")

    assert await coordinator.execute_external(scope, completed, "run", {"password": "secret"}, run)
    with pytest.raises(TimeoutError):
        await coordinator.execute_external(scope, unknown, "run", {"password": "secret"}, uncertain)
    restarted = MutationCoordinator(store, profile=tmp_path)
    assert await restarted.execute_external(
        scope, completed, "run", {"password": "secret"}, run
    ) == {"id": "job-1"}
    with pytest.raises(MutationConflictError):
        await restarted.execute_external(scope, completed, "run", {"password": "changed"}, run)
    with pytest.raises(UnknownOutcomeError):
        await restarted.execute_external(scope, unknown, "run", {"password": "secret"}, run)
    assert calls == 2
    assert "secret" not in repr(store.records)
    assert len((tmp_path / "mutation.key").read_bytes()) == 32
