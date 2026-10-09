"""Live scoped activity, explicit controls and bounded terminal output."""

from urllib.parse import urlencode
from uuid import UUID

from pydantic import RootModel, SecretStr
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from shared.activity import (
    ActionResult,
    ActivitySnapshot,
    ConsoleHandle,
    ConsoleOpen,
    RemoteAction,
    RemoteItem,
    TerminalCommand,
    TerminalOutput,
)
from shared.framework import ConnectionStatus
from shared.tools import EmptyResponse, ToolJob


class ActivityPanel(QWidget):
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
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Sessions, jobs and console"))
        self.connection = QLabel(
            "Connect to Metasploit in Settings. Local analysis jobs work offline."
        )
        root.addWidget(self.connection)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Kind", "ID", "Name / state", "Peer", "Ownership"])
        self.tree.currentItemChanged.connect(self.remember_selection)
        root.addWidget(self.tree)
        buttons = QHBoxLayout()
        for title, callback in (
            ("Refresh", self.refresh),
            ("Import into workspace", self.claim),
            ("Stop selected", self.stop),
            ("Open session terminal", self.session_terminal),
            ("Open console", self.open_console),
            ("Close terminal view", self.close_terminal),
            ("Redacted history", self.history),
        ):
            button = QPushButton(title)
            button.clicked.connect(callback)
            buttons.addWidget(button)
        root.addLayout(buttons)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(10000)
        root.addWidget(self.output, 1)
        command_row = QHBoxLayout()
        self.command = QLineEdit()
        self.command.setMaxLength(65536)
        self.command.setPlaceholderText("Command for the explicitly opened terminal")
        send = QPushButton("Send")
        command_row.addWidget(self.command)
        command_row.addWidget(send)
        root.addLayout(command_row)
        send.clicked.connect(self.send)
        self.command.returnPressed.connect(self.send)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.tick)
        self.timer.start()

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
        if key == "workspace":
            self.snapshot = self.terminal = None
            self._selection = None
            self.sequence = 0
            self._loading = self._reading = False
            self.tree.clear()
            self.output.clear()
            self.command.clear()
        elif key == "activity-snapshot" and isinstance(value, ActivitySnapshot):
            self._loading = False
            self.snapshot = value
            self.connection.setText("Framework " + str(value.framework_id))
            # Preserve local rows when refreshing the remote snapshot.
            for index in reversed(range(self.tree.topLevelItemCount())):
                item = self.tree.topLevelItem(index)
                if item and isinstance(item.data(0, Qt.ItemDataRole.UserRole), RemoteItem):
                    self.tree.takeTopLevelItem(index)
            for row in value.items:
                item = QTreeWidgetItem(
                    [
                        row.kind,
                        row.remote_id,
                        row.name,
                        row.peer,
                        "This workspace" if row.workspace_id else "Unassigned — import to control",
                    ]
                )
                item.setData(0, Qt.ItemDataRole.UserRole, row)
                self.tree.addTopLevelItem(item)
        elif key == "activity-local" and isinstance(value, RootModel):
            for index in reversed(range(self.tree.topLevelItemCount())):
                item = self.tree.topLevelItem(index)
                if item and isinstance(item.data(0, Qt.ItemDataRole.UserRole), ToolJob):
                    self.tree.takeTopLevelItem(index)
            for job in value.root:
                item = QTreeWidgetItem(
                    ["Local", str(job.id), job.tool_id + " · " + job.status, "", "This workspace"]
                )
                item.setData(0, Qt.ItemDataRole.UserRole, job)
                self.tree.addTopLevelItem(item)
        elif key == "activity-connection" and isinstance(value, ConnectionStatus):
            if value.instance_id and value.state != "Offline" and self.vm.workspace_id:
                self.vm.mutate(
                    "terminal-open",
                    "POST",
                    "/api/v1/activity/console",
                    ConsoleHandle,
                    ConsoleOpen(
                        workspace_id=self.vm.workspace_id, framework_id=UUID(value.instance_id)
                    ),
                )
        elif key == "terminal-open" and isinstance(value, ConsoleHandle):
            self.terminal = value
            self.terminal_kind = "console"
            self.sequence = 0
            self._reading = False
            self.vm.invalidate("terminal-output")
            self.output.clear()
            self.read_output()
        elif key == "terminal-output" and isinstance(value, TerminalOutput):
            self._reading = False
            self.sequence = value.sequence
            if value.truncated:
                self.output.appendPlainText(
                    "Older terminal output was discarded at the display limit."
                )
            if value.lines:
                self.output.appendPlainText("\n".join(value.lines))
        elif key == "terminal-history" and isinstance(value, RootModel):
            self.output.appendPlainText("\n".join(value.root))
        elif key in {"terminal-command", "activity-action"}:
            self.output.appendPlainText("Action completed.")
            self.refresh()
        elif (
            key == "event"
            and isinstance(value, dict)
            and value.get("topic") in {"activity", "module-launch"}
        ):
            self.refresh()

        self.restore_selection()

    def error(self, key: str, message: str) -> None:
        if key.startswith(("activity", "terminal")):
            self._loading = self._reading = False
            self.connection.setText(message)
            if key == "terminal-command":
                self.output.appendPlainText(
                    message + " Check state before entering another command."
                )
