from __future__ import annotations

import asyncio
import tempfile
import unittest
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from uuid import uuid4

import httpx
from fastapi import FastAPI, WebSocket
from pydantic import SecretStr
from websockets.asyncio.client import connect

from backend.auth import authenticate_websocket
from backend.bootstrap import prepare_backend, read_locator, verify_existing, wait_ready
from backend.tls import ensure_tls


class LiveTLS(unittest.IsolatedAsyncioTestCase):
    async def test_readiness_waits_for_delayed_application_lifespan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = prepare_backend(Path(directory))
            app = instance.server.config.app
            original_lifespan = app.router.lifespan_context
            entered, release = asyncio.Event(), asyncio.Event()

            @asynccontextmanager
            async def delayed_lifespan(app: FastAPI) -> AsyncIterator[None]:
                entered.set()
                await release.wait()
                async with original_lifespan(app):
                    yield

            app.router.lifespan_context = delayed_lifespan
            serving = asyncio.create_task(instance.serve())
            await asyncio.wait_for(entered.wait(), 2)
            self.assertFalse(instance.server.started)
            # Exceed the one-second request timeout while retaining the overall budget.
            timer = asyncio.get_running_loop().call_later(1.2, release.set)
            try:
                await wait_ready(instance.locator, instance.tls, timeout=4)
                self.assertTrue(instance.server.started)
                self.assertIsNotNone(app.state.workspaces.active_id)
            finally:
                timer.cancel()
                release.set()
                instance.stop()
                await asyncio.wait_for(serving, 10)

    async def test_fresh_profile_https_wss_identity_and_clean_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            instance = prepare_backend(profile)
            app = instance.server.config.app
            token = instance.locator.token.get_secret_value()

            @app.websocket("/ws/fixture")
            async def fixture(websocket: WebSocket) -> None:
                if await authenticate_websocket(websocket, token, app.state.allowed_origins):
                    await websocket.accept()
                    await websocket.send_json({"instance_id": str(instance.locator.instance_id)})
                    await websocket.close()

            task = asyncio.create_task(instance.serve())
            try:
                await wait_ready(instance.locator, instance.tls)
                url = f"https://127.0.0.1:{instance.locator.port}"
                async with httpx.AsyncClient(
                    verify=instance.tls.client_context(), trust_env=False
                ) as client:
                    self.assertEqual((await client.get(url + "/api/v1/health")).status_code, 401)
                    response = await client.get(
                        url + "/api/v1/health", headers={"Authorization": "Bearer " + token}
                    )
                    self.assertEqual(response.status_code, 200)
                self.assertTrue(await verify_existing(profile, instance.locator))
                with self.assertRaises(httpx.HTTPStatusError) as unauthorized:
                    await wait_ready(
                        instance.locator.model_copy(update={"token": SecretStr("c" * 64)}),
                        instance.tls,
                    )
                self.assertEqual(unauthorized.exception.response.status_code, 401)
                with self.assertRaisesRegex(ValueError, "identity mismatch"):
                    await wait_ready(
                        instance.locator.model_copy(update={"instance_id": uuid4()}), instance.tls
                    )
                async with connect(
                    url.replace("https:", "wss:") + "/ws/fixture",
                    ssl=instance.tls.client_context(),
                    proxy=None,
                    additional_headers={"Authorization": "Bearer " + token},
                ) as ws:
                    self.assertIn(str(instance.locator.instance_id), await ws.recv())
                untrusted_tls = ensure_tls(profile / "untrusted-client")
                with self.assertRaises(httpx.ConnectError):
                    await wait_ready(instance.locator, untrusted_tls, timeout=0.5)
            finally:
                instance.stop()
                await asyncio.wait_for(task, 10)
            locator = read_locator(profile)
            self.assertIsNotNone(locator)
            assert locator is not None
            self.assertTrue(locator.clean_exit)


if __name__ == "__main__":
    unittest.main()
