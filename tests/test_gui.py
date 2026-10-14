"""Real HTTPS Qt tool flows and lifecycle checks (one PyQt6 runtime)."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import tempfile
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import patch

from PyQt6.QtCore import QThread, QTimer
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication, QLineEdit

from backend.bootstrap import InstanceLocator
from backend.tls import TLSMaterial
from frontend.main_window import MainWindow
from frontend.runtime import BackendThread
from frontend.theme import apply_theme
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from shared.tools import AnomalyOptions


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
        apply_theme(cls.app, "dark")

    def wait_until(self, predicate, timeout=10000):
        for _ in range(timeout // 10):
            if predicate():
                return
            QTest.qWait(10)
        self.fail("REST background operation did not finish in time")

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.backend = BackendThread(Path(self.folder.name))
        received, errors = [], []
        self.backend.ready.connect(lambda locator, tls, owned: received.append((locator, tls)))
        self.backend.failed.connect(errors.append)
        self.backend.start()
        self.wait_until(lambda: received or errors)
        self.assertFalse(errors, errors)
        locator, tls = received[0]
        self.assertIsInstance(locator, InstanceLocator)
        self.assertIsInstance(tls, TLSMaterial)
        self.vm = ToolsViewModel(
            f"https://127.0.0.1:{locator.port}",
            tls.client_context(),
            locator.token.get_secret_value(),
        )
        self.window = MainWindow(self.vm)
        self.window.show()
        self.vm.refresh_tools()

    def tearDown(self):
        self.window.close()
        self.backend.stop()
        self.assertTrue(self.backend.wait(15000))
        self.folder.cleanup()

    def test_navigation_opens_seven_panels_and_real_readiness(self):
        self.assertEqual(len(self.window.panels), 7)
        for index in range(1, 8):
            self.window.stack.setCurrentWidget(list(self.window.panels.values())[index - 1])
            self.assertIsInstance(self.window.stack.currentWidget(), ToolPanel)
        self.wait_until(lambda: self.window.tool_table.topLevelItemCount() == 7)
        names = {self.window.tool_table.topLevelItem(index).text(0) for index in range(7)}
        self.assertIn("Caesar Cipher", names)
        self.assertIn("Password Strength", names)
        self.assertIn("Fundamentals", self.window.readiness_label.text())
        for index in range(7):
            row = self.window.tool_table.topLevelItem(index)
            actions = self.window.tool_table.itemWidget(row, 3)
            from PyQt6.QtWidgets import QPushButton

            self.assertEqual(
                [button.text() for button in actions.findChildren(QPushButton)],
                ["Open GUI", "Open in Terminal"],
            )

    def test_fundamentals_terminal_runs_real_cipher_password_and_file_jobs(self):
        import json

        caesar = self.window.panels["caesar"]
        caesar.terminal_button.click()
        caesar.command.setText('run {"text":"Hello", "shift":3}')
        caesar.command.returnPressed.emit()
        self.wait_until(lambda: "Khoor" in caesar.output.toPlainText())
        password = self.window.panels["password-strength"]
        password.terminal_button.click()
        password.command.setText('run {"password":"practice password"}')
        password.command.returnPressed.emit()
        self.wait_until(lambda: '"bits"' in password.output.toPlainText())
        self.assertEqual(password.command.echoMode(), QLineEdit.EchoMode.Password)
        self.assertNotIn("practice password", password.output.toPlainText())
        detector = self.window.panels["dos-detector"]
        detector.terminal_button.click()
        detector.command.setText(
            "run "
            + json.dumps(
                {
                    "file": str(Path(__file__).resolve().parent.parent / "examples/requests.csv"),
                    "threshold": 1,
                }
            )
        )
        detector.command.returnPressed.emit()
        self.wait_until(lambda: '"count"' in detector.output.toPlainText())
        detector.command.setText("clear")
        detector.command.returnPressed.emit()
        self.assertEqual(detector.output.toPlainText(), "")

    def test_password_clear_restores_mask_and_erases_backend_job(self):
        panel = self.window.panels["password-strength"]
        panel.password.setText("practice password")
        panel.show_password.setChecked(True)
        panel.run_button.click()
        self.wait_until(lambda: '"bits"' in panel.output.toPlainText())
        self.assertNotIn("practice password", panel.output.toPlainText())
        self.assertNotIn("**********", panel.output.toPlainText())
        panel.clear_button.click()
        self.assertEqual(panel.password.text(), "")
        self.assertEqual(panel.password.echoMode(), QLineEdit.EchoMode.Password)
        self.assertEqual(panel.output.toPlainText(), "")
        self.wait_until(lambda: not self.vm._worker._owned_jobs)

    def test_real_rest_worker_is_responsive_delivers_on_gui_thread_and_cancels(self):
        from toolkit.modules import password_strength

        entered, release = Event(), Event()
        original = password_strength.analyze_password

        def delayed(password):
            entered.set()
            release.wait(2)
            return original(password)

        panel = self.window.panels["password-strength"]
        panel.password.setText("practice password")
        ticks, threads = [], []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(10)
        self.vm.job_changed.connect(lambda *_: threads.append(QThread.currentThread()))
        try:
            with patch.object(password_strength, "analyze_password", side_effect=delayed):
                panel.run_button.click()
                self.wait_until(entered.is_set)
                QTest.qWait(100)
                self.assertGreater(len(ticks), 3)
                panel.cancel_button.click()
                app = self.backend.instance.server.config.app
                self.wait_until(
                    lambda: any(
                        record.context.cancel_event.is_set()
                        for record in app.state.jobs.records.values()
                    )
                )
                release.set()
                self.wait_until(lambda: panel.status.text() == "Cancelled")
                self.assertEqual(panel.output.toPlainText(), "")
                self.assertTrue(all(thread == self.app.thread() for thread in threads))
        finally:
            release.set()
            timer.stop()

    def test_anomaly_controls_and_infinity_display(self):
        panel = self.window.panels["anomaly-detector"]
        panel.interval.setValue(2)
        panel.baseline.setValue(4)
        panel.threshold.setValue(1.5)
        self.assertEqual(
            panel.options(), AnomalyOptions(bin_seconds=2, baseline_bins=4, threshold=1.5)
        )
        panel.show_result({"anomalies": [{"zscore": None, "score_kind": "positive_infinity"}]})
        self.assertIn("∞", panel.output.toPlainText())

    def test_sql_target_a_b_a_invalidates_forms_and_post(self):
        panel = self.window.panels["sql-checker"]
        generation = panel.target_generation
        panel.post.setChecked(True)
        original = panel.url.text()
        panel.url.setText("http://127.0.0.1:8001/")
        panel.url.setText(original)
        self.assertEqual(panel.target_generation, generation + 2)
        self.assertFalse(panel.post.isChecked())
        panel.show_result(
            {
                "discovery_id": "00000000-0000-4000-8000-000000000001",
                "generation": generation,
                "source_url": original,
                "forms": [],
            }
        )
        self.assertIsNone(panel.discovery_id)
        self.assertFalse(panel.test_button.isEnabled())

    def test_sql_oversized_edit_reports_limit_without_submission(self):
        panel = self.window.panels["sql-checker"]
        panel.show_result(
            {
                "discovery_id": "00000000-0000-4000-8000-000000000001",
                "generation": panel.target_generation,
                "source_url": panel.url.text(),
                "forms": [
                    {
                        "action": panel.url.text(),
                        "method": "GET",
                        "fields": [{"name": "query", "value": "original"}],
                        "probe_indices": [0],
                    }
                ],
            }
        )
        edited = "sensitive-edit-sentinel" + "x" * (65537 - 23)
        self.assertEqual(len(edited), 65537)
        panel.fields.item(0, 1).setText(edited)
        discovery_id = panel.discovery_id
        pending = dict(self.vm._pending)

        panel.test_selected()

        self.assertIn("65,536", panel.status.text())
        self.assertNotIn("sensitive-edit-sentinel", panel.status.text())
        self.assertEqual(self.vm._pending, pending)
        self.assertFalse(self.backend.instance.server.config.app.state.jobs.records)
        self.assertEqual(panel.discovery_id, discovery_id)
        self.assertEqual(panel.fields.item(0, 1).text(), edited)
        self.assertEqual(panel.forms.count(), 1)
        self.assertTrue(panel.test_button.isEnabled())

    def test_shutdown_erases_a_submission_before_queued_gui_signal_delivery(self):
        panel = self.window.panels["caesar"]
        panel.source.setPlainText("Close immediately")
        panel.run_button.click()
        self.window.close()
        self.assertFalse(self.vm.is_running)
        self.assertFalse(self.vm._worker._owned_jobs)

    def test_resources_resolve_from_another_working_directory(self):
        from toolkit.core import resource_text

        original = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                self.assertEqual(len(resource_text("common_passwords.txt").splitlines()), 1000)
            finally:
                os.chdir(original)


if __name__ == "__main__":
    unittest.main()
