from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from backend.bootstrap import InstanceLocator
from frontend.runtime import BackendThread
from frontend.viewmodels.base_vm import BaseViewModel


class QtBootstrapTests(unittest.TestCase):
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
