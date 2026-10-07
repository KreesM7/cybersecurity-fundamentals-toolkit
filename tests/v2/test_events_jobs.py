from __future__ import annotations

import asyncio
import unittest
from uuid import uuid4

from backend.events import EventHub, SlowConsumerError
from backend.jobs import JobManager, JobQueueFullError


class EventJobTests(unittest.IsolatedAsyncioTestCase):
    async def test_slow_consumer_disconnects_without_blocking_other_subscribers(self) -> None:
        hub = EventHub(queue_size=2)
        workspace = uuid4()
        slow = hub.subscribe("jobs", workspace)
        fast = hub.subscribe("jobs", workspace)
        other = hub.subscribe("jobs", uuid4())
        for i in range(3):
            await hub.publish("jobs", {"count": i}, workspace_id=workspace)
            self.assertEqual((await fast.receive()).data, {"count": i})
        with self.assertRaises(SlowConsumerError):
            await slow.receive()
        self.assertTrue(other.queue.empty())
        self.assertLessEqual(len(hub.recent), 100)
        await hub.close()

    async def test_two_active_32_queued_cancel_and_workspace_identity(self) -> None:
        manager = JobManager(EventHub())
        gate = asyncio.Event()
        workspace = uuid4()
        releases = 0

        async def release() -> None:
            nonlocal releases
            releases += 1

        async def work(context: object) -> dict[str, bool]:
            await gate.wait()
            return {"complete": True}

        jobs = [
            await manager.submit("fixture", workspace, work, cleanup=release) for _ in range(34)
        ]
        self.assertEqual(manager.active_count, 2)
        self.assertEqual(manager.queued_count, 32)
        with self.assertRaises(JobQueueFullError):
            await manager.submit("fixture", workspace, work)
        await manager.cancel(jobs[-1].id, workspace)
        self.assertEqual(manager.queued_count, 31)
        self.assertEqual(releases, 1)
        self.assertIsNone(manager.records[jobs[-1].id].work)
        self.assertEqual(manager.get(jobs[0].id, workspace).workspace_id, workspace)
        with self.assertRaises(KeyError):
            manager.get(jobs[0].id, uuid4())
        gate.set()
        await manager.wait_idle()
        self.assertEqual(releases, 34)
        self.assertTrue(all(record.work is None for record in manager.records.values()))
        await manager.close()

    async def test_cleanup_failure_does_not_leave_active_slot_or_secret_closure(self) -> None:
        manager = JobManager(EventHub())

        async def work(context: object) -> dict[str, bool]:
            return {"complete": True}

        async def cleanup() -> None:
            raise RuntimeError("sentinel-secret must not enter events")

        job = await manager.submit("fixture", uuid4(), work, cleanup=cleanup)
        await asyncio.wait_for(manager.wait_idle(), 2)
        self.assertEqual(manager.active_count, 0)
        record = manager.records[job.id]
        self.assertIsNone(record.work)
        self.assertIsNone(record.cleanup)
        self.assertEqual(record.snapshot.status, "failed")
        self.assertNotIn("sentinel-secret", str(manager.hub.recent))
        await manager.close()

    async def test_shutdown_waits_for_owned_work_and_releases_all_leases(self) -> None:
        manager = JobManager(EventHub())
        started = asyncio.Event()
        released = asyncio.Event()

        async def work(context: object) -> None:
            started.set()
            await asyncio.Event().wait()

        async def cleanup() -> None:
            released.set()

        job = await manager.submit("fixture", uuid4(), work, cleanup=cleanup)
        await started.wait()
        await manager.close()
        self.assertTrue(released.is_set())
        self.assertEqual(manager.records[job.id].snapshot.status, "cancelled")

    async def test_cancellation_before_worker_starts_releases_lease(self) -> None:
        manager = JobManager(EventHub())
        released = asyncio.Event()

        async def work(context: object) -> None:
            self.fail("A cancelled runner must not begin work")

        async def cleanup() -> None:
            released.set()

        job = await manager.submit("fixture", uuid4(), work, cleanup=cleanup)
        await manager.cancel(job.id, job.workspace_id)
        self.assertTrue(released.is_set())
        self.assertEqual(manager.active_count, 0)
        await manager.close()


if __name__ == "__main__":
    unittest.main()
