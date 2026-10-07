import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PySide6.QtCore import QThread, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QCheckBox, QComboBox, QLineEdit, QPlainTextEdit, QPushButton, QTableWidget
from toolkit.app import MainWindow, configure_theme
from toolkit.tasks import AppContext
from toolkit.widgets import TaskPanel


class GuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)
        configure_theme(cls.app)

    def wait_until(self, predicate, timeout=3000):
        for _ in range(timeout // 10):
            if predicate():
                return
            QTest.qWait(10)
        self.fail('Background operation did not finish in time.')

    def test_navigation_opens_every_panel(self):
        window = MainWindow()
        window.show()
        self.assertEqual(len(window.entries), 7)
        for row in range(1, 8):
            window.sidebar.setCurrentRow(row)
            QTest.qWait(10)
            self.assertIsInstance(window.stack.currentWidget(), TaskPanel)
        window.sidebar.setCurrentRow(0)
        self.assertIs(window.stack.currentWidget(), window.home)
        window.close()

    def test_tasks_keep_gui_responsive_deliver_on_main_thread_and_cancel(self):
        context = AppContext()
        results, errors, ticks = [], [], []
        timer = QTimer()
        timer.timeout.connect(lambda: ticks.append(1))
        timer.start(10)
        context.run_task(lambda task: (task.wait(0.2), 42)[1],
                         lambda value: results.append((value, QThread.currentThread())), errors.append)
        self.wait_until(lambda: not context.jobs)
        self.assertEqual(results[0], (42, self.app.thread()))
        self.assertGreater(len(ticks), 3)
        handle = context.run_task(lambda task: task.wait(10), results.append, errors.append)
        QTest.qWait(30)
        handle.cancel()
        self.wait_until(lambda: not context.jobs)
        self.assertIn('Cancelled', errors[0])
        timer.stop()

    def test_shutdown_cancels_and_waits_for_workers(self):
        window = MainWindow()
        window.show()
        errors = []
        window.context.run_task(lambda task: task.wait(10), lambda result: None, errors.append)
        QTest.qWait(20)
        window.close()
        self.wait_until(lambda: not window.isVisible())
        self.assertFalse(window.context.jobs)
        self.assertIn('Cancelled', errors[0])

    def test_password_clear_restores_mask_and_clears_results(self):
        from toolkit.modules.password_strength import create_panel
        context = AppContext()
        panel = create_panel(context)
        password = panel.findChild(QLineEdit)
        output = panel.findChild(QPlainTextEdit)
        password.setText('practice password')
        panel.run_button.click()
        self.wait_until(lambda: not context.jobs)
        self.assertIn('Estimated strength', output.toPlainText())
        next(b for b in panel.findChildren(QPushButton) if b.text() == 'Clear').click()
        self.assertEqual(password.text(), '')
        self.assertEqual(output.toPlainText(), '')
        self.assertEqual(password.echoMode(), QLineEdit.EchoMode.Password)
        panel.close()

    def test_scanner_custom_target_requires_permission_and_delivers_results(self):
        from types import SimpleNamespace
        from toolkit.modules import network_scanner as module
        xml = b'''<nmaprun args="fixture"><scaninfo type="connect" protocol="tcp" services="80"/>
          <host><status state="up" reason="user-set"/><address addr="93.184.216.34" addrtype="ipv4"/>
          <ports><port protocol="tcp" portid="80"><state state="closed" reason="reset"/></port></ports></host>
          <runstats><finished timestr="fixture" elapsed="0.1"/><hosts up="1" down="0" total="1"/></runstats></nmaprun>'''
        context = AppContext()
        with patch.object(module, 'list_interfaces', return_value=[]), \
             patch.object(module, 'nmap_path', return_value='fixture-nmap.exe'), \
             patch('subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=xml, stderr=b'')):
            panel = module.create_panel(context)
            self.assertIsNone(panel.findChild(QComboBox).currentData())
            panel.findChild(QLineEdit).setText('93.184.216.34')
            panel.run_button.click()
            self.assertFalse(context.jobs)
            self.assertIn('permission', panel.status.text())
            panel.findChild(QCheckBox).setChecked(True)
            panel.run_button.click()
            self.wait_until(lambda: not context.jobs)
            self.assertEqual(panel.findChild(QTableWidget).item(0, 0).text(), '93.184.216.34')
            self.assertIn('1 responding', panel.status.text())
            panel.close()

    def test_missing_dependencies_do_not_prevent_navigation(self):
        import builtins
        real_import = builtins.__import__
        missing = {'nmap', 'psutil', 'magic', 'zxcvbn', 'urllib3', 'bs4', 'scapy'}

        def limited_import(name, *args, **kwargs):
            if name.split('.')[0] in missing:
                raise ImportError('Fixture: missing ' + name)
            return real_import(name, *args, **kwargs)

        with patch('builtins.__import__', side_effect=limited_import):
            window = MainWindow()
            for row in range(1, 8):
                window.sidebar.setCurrentRow(row)
                self.assertIsInstance(window.stack.currentWidget(), TaskPanel)
            statuses = [window.readiness_table.item(row, 1).text() for row in range(7)]
            self.assertTrue(any('Setup' in status for status in statuses))
            window.close()

    def test_changing_web_target_clears_permission_and_loaded_forms(self):
        from toolkit.modules import sql_checker as module
        context = AppContext()
        panel = module.create_panel(context)
        form = module.FormSpec('http://localhost:8000/search', 'GET', [('q', 'hello')])
        discovery = module.Discovery('http://localhost:8000/', [form], [])
        with patch.object(module, 'discover_forms', return_value=discovery):
            panel.run_button.click()
            self.wait_until(lambda: not context.jobs)
        permission = next(box for box in panel.findChildren(QCheckBox) if 'permission' in box.text())
        test_button = next(button for button in panel.findChildren(QPushButton) if button.text() == 'Test selected form')
        self.assertTrue(test_button.isEnabled())
        permission.setChecked(True)
        panel.findChild(QLineEdit).setText('https://example.com/')
        self.assertFalse(permission.isChecked())
        self.assertFalse(test_button.isEnabled())
        self.assertIsNone(panel.discovery)
        self.assertEqual(panel.findChild(QComboBox).count(), 0)
        panel.close()

    def test_web_target_edits_discard_late_discovery_and_probe_results(self):
        from threading import Event
        from toolkit.modules import sql_checker as module
        form = module.FormSpec('http://localhost:8000/search', 'GET', [('q', 'hello')])
        discovery = module.Discovery('http://localhost:8000/', [form], [])
        for operation in ('discovery', 'probes'):
            with self.subTest(operation=operation):
                context = AppContext()
                panel = module.create_panel(context)
                entered, release = Event(), Event()
                target = panel.findChild(QLineEdit)
                def delayed(*args, **kwargs):
                    entered.set()
                    release.wait(2)
                    return discovery if operation == 'discovery' else [
                        module.Finding('q', "'", 500, 'Old target evidence')]
                try:
                    if operation == 'probes':
                        with patch.object(module, 'discover_forms', return_value=discovery):
                            panel.run_button.click()
                            self.wait_until(lambda: not context.jobs)
                        next(box for box in panel.findChildren(QCheckBox) if 'permission' in box.text()).setChecked(True)
                    attribute = 'discover_forms' if operation == 'discovery' else 'test_form'
                    with patch.object(module, attribute, side_effect=delayed):
                        if operation == 'discovery':
                            panel.run_button.click()
                        else:
                            next(button for button in panel.findChildren(QPushButton)
                                 if button.text() == 'Test selected form').click()
                        self.wait_until(entered.is_set)
                        target.setText('https://example.com/')
                        target.setText('http://localhost:8000/')
                        release.set()
                        self.wait_until(lambda: not context.jobs)
                    self.assertIsNone(panel.discovery)
                    self.assertTrue(all(table.rowCount() == 0 for table in panel.findChildren(QTableWidget)))
                finally:
                    release.set()
                    self.wait_until(lambda: not context.jobs)
                    panel.close()

    def test_resources_resolve_from_another_working_directory(self):
        from toolkit.core import resource_text
        original = Path.cwd()
        with tempfile.TemporaryDirectory() as folder:
            try:
                os.chdir(folder)
                self.assertIn('password', resource_text('common_passwords.txt').splitlines())
                self.assertIn('password', AppContext().resource_text('common_passwords.txt').splitlines())
            finally:
                os.chdir(original)
