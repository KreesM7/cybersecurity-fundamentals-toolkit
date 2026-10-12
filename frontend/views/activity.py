"""Live scoped activity, explicit controls and bounded terminal output."""

from urllib.parse import urlencode

from pydantic import RootModel, SecretStr
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.activity_controls import build_activity
from frontend.widgets.activity_state import render_activity
from frontend.widgets.presentation import StatusBadge, enhance
from shared.activity import (
    ActionResult,
    ActivitySnapshot,
    ConsoleHandle,
    RemoteAction,
    RemoteItem,
    TerminalCommand,
    TerminalOutput,
)
from shared.framework import ConnectionStatus
from shared.modules import ModuleLibrary
from shared.tools import EmptyResponse, ToolJob


class ActivityPanel(QWidget):
    connection: StatusBadge
    tabs: QTabWidget
    tree: QTreeWidget
    context: QComboBox
    output: QPlainTextEdit
    advanced: QCheckBox
    activity_toolbar: QWidget
    raw_controls: QWidget
    command: QLineEdit

    guided_stops: list[QPushButton]
    module_requested = pyqtSignal(str)
    navigate_requested = pyqtSignal(str)

    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.snapshot: ActivitySnapshot | None = None
        self.terminal: ConsoleHandle | None = None
        self.terminal_kind = "console"
        self.sequence = 0
        self._loading = False
        self._reading = False
        self._selection: tuple[str, str] | None = None
        self.library = ModuleLibrary()
        build_activity(self)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.tick)
        self.timer.start()
        enhance(self)

    def tick(self) -> None:
        if self.isVisible():
            self.refresh()
            self.read_output()

    def refresh(self) -> None:
        if self.vm.workspace_id and not self._loading:
            self._loading = True
            self.vm.get(
                "activity-snapshot",
                f"/api/v1/activity?workspace_id={self.vm.workspace_id}",
                ActivitySnapshot,
            )
            self.vm.get(
                "activity-local",
                f"/api/v1/jobs?workspace_id={self.vm.workspace_id}",
                RootModel[list[ToolJob]],
            )

    def selected(self) -> RemoteItem | ToolJob | None:
        item = self.tree.currentItem()
        return item.data(0, Qt.ItemDataRole.UserRole) if item else None

    def remember_selection(
        self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None
    ) -> None:
        if current:
            self._selection = current.text(0), current.text(1)

    def restore_selection(self) -> None:
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item and self._selection == (item.text(0), item.text(1)):
                self.tree.setCurrentItem(item)
                return

    def remote_action(self, name: str) -> None:
        selected = self.selected()
        if not isinstance(selected, RemoteItem) or not self.snapshot or not self.vm.workspace_id:
            return
        if (
            QMessageBox.question(
                self,
                name.title(),
                f"{name.title()} {selected.kind} {selected.remote_id}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        data = RemoteAction(
            workspace_id=self.vm.workspace_id,
            framework_id=self.snapshot.framework_id,
            remote_id=selected.remote_id,
            kind=selected.kind,
            confirmed=True,
        )
        self.vm.mutate("activity-action", "POST", "/api/v1/activity/" + name, ActionResult, data)

    def claim(self) -> None:
        self.remote_action("claim")

    def stop(self) -> None:
        selected = self.selected()
        if isinstance(selected, ToolJob):
            if (
                QMessageBox.question(
                    self,
                    "Cancel job?",
                    "Cancel this local analysis job?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self.vm.mutate(
                    "activity-action",
                    "POST",
                    f"/api/v1/jobs/{selected.id}/cancel?workspace_id={selected.workspace_id}",
                    EmptyResponse,
                )
        else:
            self.remote_action("stop")

    def session_terminal(self) -> None:
        row = self.selected()
        if (
            isinstance(row, RemoteItem)
            and row.kind == "session"
            and row.workspace_id == self.vm.workspace_id
            and self.snapshot
        ):
            if row.session_type not in {"shell", "meterpreter"}:
                self.output.appendPlainText("This session type does not support this terminal.")
                return
            self.terminal = ConsoleHandle(
                workspace_id=self.snapshot.workspace_id,
                framework_id=self.snapshot.framework_id,
                remote_id=row.remote_id,
            )
            self.terminal_kind = row.session_type
            self.sequence = 0
            self._reading = False
            self.vm.invalidate("terminal-output")
            self.output.clear()
            self.tabs.setCurrentIndex(2)
            self.read_output()

    def open_console(self) -> None:
        self.vm.get("activity-connection", "/api/v1/connection", ConnectionStatus)

    def close_terminal(self) -> None:
        if self.terminal and self.terminal_kind == "console":
            self.vm.mutate(
                "terminal-close",
                "POST",
                "/api/v1/activity/console/close",
                ActionResult,
                self.terminal,
            )
        self.terminal = None
        self._reading = False
        self.vm.invalidate("terminal-output")
        self.output.clear()
        self.command.clear()

    def read_output(self) -> None:
        if self.terminal and not self._reading:
            self._reading = True
            self.vm.get(
                "terminal-output",
                "/api/v1/activity/output?"
                + urlencode(
                    self.terminal.model_dump(mode="json")
                    | {"kind": self.terminal_kind, "since": self.sequence}
                ),
                TerminalOutput,
            )

    def send(self) -> None:
        if not self.terminal or not self.command.text().strip():
            return
        data = TerminalCommand.model_validate(
            self.terminal.model_dump()
            | {"kind": self.terminal_kind, "command": SecretStr(self.command.text())}
        )
        self.command.clear()
        self.vm.mutate("terminal-command", "POST", "/api/v1/activity/command", ActionResult, data)

    def history(self) -> None:
        if self.vm.workspace_id:
            self.vm.get(
                "terminal-history",
                f"/api/v1/activity/history?workspace_id={self.vm.workspace_id}",
                RootModel[list[str]],
            )

    def update_state(self, key: str, value: object) -> None:
        render_activity(self, key, value)

    def error(self, key: str, message: str) -> None:
        if key.startswith(("activity", "terminal")):
            self._loading = self._reading = False
            self.connection.setText(message)
            if key == "terminal-command":
                self.output.appendPlainText(
                    message + " Check state before entering another command."
                )
