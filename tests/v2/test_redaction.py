from __future__ import annotations

import unittest
from threading import Event
from uuid import uuid4

from backend.events import EventHub
from backend.jobs import JobContext
from backend.redaction import Redactor


class RedactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_job_progress_redacts_before_its_shorter_limit(self) -> None:
        hub = EventHub()
        hub.redactor.register("boundary-secret")
        context = JobContext(Event(), hub, uuid4(), uuid4())
        await context.progress("x" * 994 + "boundary-secret")
        self.assertEqual(
            hub.recent[-1].data,
            {"id": str(context.job_id), "progress": "x" * 994 + "[REDAC"},
        )
        await hub.close()

    async def test_registered_secrets_are_removed_before_truncation_and_retention(self) -> None:
        for prefix, secret in (("x" * 9994, "boundary-secret"), ("", "z" * 65536)):
            with self.subTest(secret_length=len(secret)):
                hub = EventHub()
                hub.redactor.register(secret)
                subscriber = hub.subscribe("console")
                await hub.publish("console", {"line": prefix + secret + " public"})
                expected = (prefix + "[REDACTED] public")[:10000]
                self.assertEqual((await subscriber.receive()).data, {"line": expected})
                self.assertEqual(hub.recent[-1].data, {"line": expected})
                await hub.close()

    async def test_nested_fields_registered_secrets_and_console_patterns_are_redacted(self) -> None:
        redactor = Redactor()
        redactor.register("sentinel-rpc-secret")
        data = redactor.clean(
            {
                "password": "secret1",
                "nested": {"access_token": "secret2", "status": "sentinel-rpc-secret"},
                "line": "set SMBPass secret3\npassword: secret4",
                "checksum": "abcdef",
            }
        )
        self.assertNotIn("secret1", str(data))
        self.assertNotIn("secret2", str(data))
        self.assertNotIn("sentinel-rpc-secret", str(data))
        self.assertNotIn("secret3", str(data))
        self.assertNotIn("secret4", str(data))
        self.assertIn("abcdef", str(data))

    async def test_events_are_redacted_before_recent_history_and_bounded(self) -> None:
        hub = EventHub()
        subscriber = hub.subscribe("console", uuid4())
        await hub.publish(
            "console", {"line": "Password = hidden-secret"}, workspace_id=subscriber.workspace_id
        )
        self.assertNotIn("hidden-secret", str(await subscriber.receive()))
        self.assertNotIn("hidden-secret", str(hub.recent))
        await hub.publish("console", {"line": "x" * 100000}, workspace_id=subscriber.workspace_id)
        self.assertLess(len((await subscriber.receive()).model_dump_json()), 65536)
        await hub.close()


if __name__ == "__main__":
    unittest.main()
