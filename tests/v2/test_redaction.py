from __future__ import annotations

import unittest
from uuid import uuid4

from backend.events import EventHub
from backend.redaction import Redactor


class RedactionTests(unittest.IsolatedAsyncioTestCase):
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
