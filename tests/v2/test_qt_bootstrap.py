from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from backend.bootstrap import InstanceLocator, prepare_backend
from frontend.runtime import BackendThread
from frontend.viewmodels.base_vm import BaseViewModel


class QtBootstrapTests(unittest.TestCase):
    def test_stale_corrupt_tls_is_repaired_but_live_owner_is_never_overwritten(self) -> None:
        app = QApplication.instance() or QApplication([])
        for live_owner in (False, True):
            with self.subTest(live_owner=live_owner), tempfile.TemporaryDirectory() as directory:
                profile = Path(directory)
                stale = prepare_backend(profile)
                stale.listener.close()
                if not live_owner:
                    stale.lease.close()
                stale.tls.server_cert.write_bytes(b"corrupt TLS material")
                thread = BackendThread(profile)
                received: list[tuple[object, object, bool]] = []
                failures: list[str] = []
                thread.ready.connect(
                    lambda locator, tls, owned: received.append((locator, tls, owned))
                )
                thread.failed.connect(failures.append)
                thread.start()
                try:
                    deadline = time.monotonic() + 15
                    while not received and not failures and time.monotonic() < deadline:
                        app.processEvents()
                        time.sleep(0.01)
                    if live_owner:
                        self.assertTrue(failures)
                        self.assertFalse(received)
                        self.assertIsNone(thread.instance)
                        self.assertEqual(
                            stale.tls.server_cert.read_bytes(), b"corrupt TLS material"
                        )
                    else:
                        self.assertFalse(failures, failures)
                        self.assertTrue(received)
                        self.assertNotEqual(
                            stale.tls.server_cert.read_bytes(), b"corrupt TLS material"
                        )
                finally:
                    thread.stop()
                    self.assertTrue(thread.wait(12000))
                    stale.lease.close()

    def test_stale_unclean_locator_with_missing_certificate_is_repaired(self) -> None:
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory)
            stale = prepare_backend(profile)
            stale.listener.close()
            stale.lease.close()
            stale.tls.server_cert.unlink()
            thread = BackendThread(profile)
            received: list[tuple[object, object, bool]] = []
            failures: list[str] = []
            thread.ready.connect(lambda locator, tls, owned: received.append((locator, tls, owned)))
            thread.failed.connect(failures.append)
            thread.start()
            try:
                deadline = time.monotonic() + 15
                while not received and not failures and time.monotonic() < deadline:
                    app.processEvents()
                    time.sleep(0.01)
                self.assertFalse(failures, failures)
                self.assertTrue(received)
                self.assertTrue(received[0][2])
                self.assertTrue(stale.tls.server_cert.exists())
            finally:
                thread.stop()
                self.assertTrue(thread.wait(12000))

    def test_backend_and_client_use_separate_threads_and_stop_cleanly(self) -> None:
        app = QApplication.instance() or QApplication([])
        with tempfile.TemporaryDirectory() as directory:
            thread = BackendThread(Path(directory))
            received: list[tuple[object, object, bool]] = []
            failures: list[str] = []
            thread.ready.connect(lambda locator, tls, owned: received.append((locator, tls, owned)))
            thread.failed.connect(failures.append)
            thread.start()
            deadline = time.monotonic() + 15
            while not received and not failures and time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.01)
            self.assertFalse(failures, failures)
            self.assertTrue(received)
            locator, tls, owned = received[0]
            assert isinstance(locator, InstanceLocator)
            self.assertTrue(owned)
            vm = BaseViewModel(
                f"https://127.0.0.1:{locator.port}",
                tls.client_context(),
                locator.token.get_secret_value(),
            )
            vm.refresh_health()
            while vm.health is None and time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.01)
            self.assertIsNotNone(vm.health)
            vm.close()
            thread.stop()
            self.assertTrue(thread.wait(12000))


if __name__ == "__main__":
    unittest.main()
