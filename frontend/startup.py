"""Bounded, asynchronous startup check; the main window opens only after completion."""

from PyQt6.QtCore import QObject, QTimer
from PyQt6.QtCore import pyqtSignal as Signal
from PyQt6.QtWidgets import QLabel

from frontend.viewmodels.app_vm import AppViewModel
from shared.desktop import StartupUpdateResult


class StartupUpdateGate(QObject):
    finished = Signal(object)

    def __init__(self, vm: AppViewModel, launcher: QLabel, *, timeout_ms: int = 7000) -> None:
        super().__init__(launcher)
        self.vm = vm
        self.launcher = launcher
        self.done = False
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(timeout_ms)
        self.timer.timeout.connect(lambda: self._finish(StartupUpdateResult(state="failed")))
        vm.state_changed.connect(self.receive)
        vm.action_error.connect(self.error)

    def start(self) -> None:
        self.launcher.setText("Checking for updates…")
        self.timer.start()
        self.vm.get("startup-updates", "/api/v1/updates/startup", StartupUpdateResult)

    def receive(self, key: str, value: object) -> None:
        if key == "startup-updates" and isinstance(value, StartupUpdateResult):
            self._finish(value)

    def error(self, key: str, message: str) -> None:
        if key == "startup-updates":
            self._finish(StartupUpdateResult(state="failed"))

    def cancel(self) -> None:
        if not self.done:
            self.done = True
            self.timer.stop()
            self.vm.invalidate("startup-updates")
            self.vm.state_changed.disconnect(self.receive)
            self.vm.action_error.disconnect(self.error)

    def _finish(self, result: StartupUpdateResult) -> None:
        if self.done:
            return
        self.cancel()
        self.finished.emit(result)
