from __future__ import annotations

import asyncio
import unittest
from threading import Event
from uuid import uuid4

from backend.events import EventHub, SlowConsumerError
from backend.jobs import JobContext, JobManager, JobQueueFullError


class EventJobTests(unittest.IsolatedAsyncioTestCase):
    async def test_shutdown_cancellation_cannot_interrupt_lease_cleanup(self) -> None:
        manager = JobManager(EventHub())
        cleanup_started, cleanup_gate = asyncio.Event(), asyncio.Event()
        released = False

        async def work(context: JobContext) -> None:
            return None

        async def cleanup() -> None:
            nonlocal released
            cleanup_started.set()
            await cleanup_gate.wait()
            released = True

        job = await manager.submit("fixture", uuid4(), work, cleanup=cleanup)
        await asyncio.wait_for(cleanup_started.wait(), 2)
        shutdown = asyncio.create_task(manager.close())
        try:
            await asyncio.sleep(0)
            shutdown.cancel()
            await asyncio.sleep(0)
            shutdown.cancel()
            done, _ = await asyncio.wait((shutdown,), timeout=0.05)
            self.assertFalse(done, "Shutdown returned before workspace cleanup completed")
            self.assertFalse(released)
            self.assertEqual(manager.active_count, 1)
        finally:
            cleanup_gate.set()
            await asyncio.gather(shutdown, return_exceptions=True)
            await manager.wait_idle()
        self.assertTrue(released)
        self.assertEqual(manager.get(job.id, job.workspace_id).status, "succeeded")

    async def test_concurrent_cancel_clear_shutdown_wait_for_native_worker(self) -> None:
        manager = JobManager(EventHub())
        loop = asyncio.get_running_loop()
        started, cancellation_seen = asyncio.Event(), asyncio.Event()
        worker_gate, worker_exited = Event(), Event()
        releases: list[bool] = []

        async def work(context: JobContext) -> None:
            def native_work() -> None:
                loop.call_soon_threadsafe(started.set)
                context.cancel_event.wait(5)
                loop.call_soon_threadsafe(cancellation_seen.set)
                worker_gate.wait(5)
                worker_exited.set()

            await context.run_sync(native_work)

        async def cleanup() -> None:
            releases.append(worker_exited.is_set())

        job = await manager.submit("fixture", uuid4(), work, cleanup=cleanup)
        await asyncio.wait_for(started.wait(), 2)
        calls = [asyncio.create_task(manager.cancel(job.id, job.workspace_id))]
        try:
            await asyncio.wait_for(cancellation_seen.wait(), 2)
            calls.extend(
                asyncio.create_task(action)
                for action in (
                    manager.cancel(job.id, job.workspace_id),
                    manager.clear(job.id, job.workspace_id),
                    manager.clear(job.id, job.workspace_id),
                    manager.close(),
                )
            )
            # A bounded wait leaves the native worker gated while all callers run.
            done, _ = await asyncio.wait(calls, timeout=0.05)
            self.assertEqual(releases, [], "Lease released before native worker exit")
            self.assertFalse(done, "Cancellation returned while its worker was still active")
            self.assertEqual(manager.active_count, 1)
        finally:
            worker_gate.set()
            results = await asyncio.gather(*calls, return_exceptions=True)
            await manager.close()
        self.assertEqual(releases, [True])
        self.assertEqual(results, [None] * len(calls))
        self.assertEqual(manager.active_count, 0)
        self.assertNotIn(job.id, manager.records)

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
