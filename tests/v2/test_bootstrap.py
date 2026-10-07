from __future__ import annotations

import secrets
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient

from backend.auth import authenticate_websocket, install_auth
from backend.bootstrap import InstanceLocator, read_locator, write_locator
from backend.tls import ensure_tls


class BootstrapTests(unittest.TestCase):
    def test_fresh_certificates_and_expired_leaf_are_renewed_before_startup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            now = datetime.now(UTC)
            first = ensure_tls(profile, now=now)
            first_ca = first.ca_cert.read_bytes()
            first_server = first.server_cert.read_bytes()
            second = ensure_tls(profile, now=now + timedelta(days=100))
            self.assertEqual(first_ca, second.ca_cert.read_bytes())
            self.assertNotEqual(first_server, second.server_cert.read_bytes())
            cert = x509.load_pem_x509_certificate(second.server_cert.read_bytes())
            self.assertGreater(cert.not_valid_after_utc, now + timedelta(days=100))
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("localhost", names.get_values_for_type(x509.DNSName))

    def test_expired_ca_is_replaced_and_bad_certificate_is_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            now = datetime.now(UTC)
            first = ensure_tls(profile, now=now)
            old_ca = first.ca_cert.read_bytes()
            second = ensure_tls(profile, now=now + timedelta(days=400))
            self.assertNotEqual(old_ca, second.ca_cert.read_bytes())
            second.server_cert.write_bytes(b"corrupt certificate")
            repaired = ensure_tls(profile, now=now + timedelta(days=400))
            x509.load_pem_x509_certificate(repaired.server_cert.read_bytes())

    def test_near_expiry_renews_but_healthy_material_is_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            now = datetime.now(UTC)
            first = ensure_tls(profile, now=now)
            original = first.server_cert.read_bytes()
            ensure_tls(profile, now=now + timedelta(days=20))
            self.assertEqual(first.server_cert.read_bytes(), original)
            ensure_tls(profile, now=now + timedelta(days=84))
            self.assertNotEqual(first.server_cert.read_bytes(), original)

    def test_locator_validates_identity_and_keeps_token_out_of_repr(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            token = secrets.token_hex(32)
            locator = InstanceLocator.fresh(44321, token, "a" * 64)
            write_locator(profile, locator)
            self.assertEqual(read_locator(profile), locator)
            self.assertNotIn(token, repr(locator))
            data = locator.model_dump(mode="json")
            data["port"] = 0
            with self.assertRaises(ValueError):
                InstanceLocator.model_validate(data)

    def test_bearer_origin_and_websocket_handshake_fail_closed(self) -> None:
        token = secrets.token_hex(32)
        app = FastAPI()
        install_auth(app, token, allowed_origins={"https://127.0.0.1:45678"})

        @app.get("/api/v1/health")
        async def health() -> dict[str, str]:
            return {"status": "ready"}

        @app.websocket("/ws/events")
        async def events(websocket: WebSocket) -> None:
            if await authenticate_websocket(websocket, token, app.state.allowed_origins):
                await websocket.accept()
                await websocket.send_json({"type": "ready"})
                await websocket.close()

        with TestClient(app) as client:
            for auth in (None, "Basic x", "Bearer wrong", "Bearer " + token + " extra"):
                headers = {"Authorization": auth} if auth else {}
                self.assertEqual(client.get("/api/v1/health", headers=headers).status_code, 401)
            headers = {"Authorization": "Bearer " + token}
            self.assertEqual(client.get("/api/v1/health", headers=headers).status_code, 200)
            self.assertEqual(
                client.get(
                    "/api/v1/health", headers={**headers, "Origin": "https://evil.test"}
                ).status_code,
                403,
            )
            with client.websocket_connect("/ws/events", headers=headers) as ws:
                self.assertEqual(ws.receive_json()["type"], "ready")
            from starlette.websockets import WebSocketDisconnect

            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect("/ws/events?token=" + token):
                    self.fail("Query-string token must not authenticate")


if __name__ == "__main__":
    unittest.main()
