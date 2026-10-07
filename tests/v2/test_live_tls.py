from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

import httpx
from fastapi import WebSocket
from websockets.asyncio.client import connect

from backend.auth import authenticate_websocket
from backend.bootstrap import prepare_backend, read_locator, verify_existing, wait_ready


class LiveTLS(unittest.IsolatedAsyncioTestCase):
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
                async with connect(
                    url.replace("https:", "wss:") + "/ws/fixture",
                    ssl=instance.tls.client_context(),
                    proxy=None,
                    additional_headers={"Authorization": "Bearer " + token},
                ) as ws:
                    self.assertIn(str(instance.locator.instance_id), await ws.recv())
                async with httpx.AsyncClient(trust_env=False) as untrusted:
                    with self.assertRaises(httpx.ConnectError):
                        await untrusted.get(url + "/api/v1/health")
            finally:
                instance.stop()
                await asyncio.wait_for(task, 10)
            locator = read_locator(profile)
            self.assertIsNotNone(locator)
            assert locator is not None
            self.assertTrue(locator.clean_exit)


if __name__ == "__main__":
    unittest.main()
