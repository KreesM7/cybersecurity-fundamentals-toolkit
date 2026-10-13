"""Explicit tool launch, session selection, terminal input and local audit display."""

from collections.abc import Callable
from uuid import UUID

from pydantic import RootModel, SecretStr
from PyQt6.QtCore import QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from frontend.theme import SPACE
from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.native_terminal import NativeTerminalView
from frontend.widgets.presentation import StatusBadge
from shared.activity import ActionResult
from shared.secdesk import (
    NativeAudit,
    NativeHandle,
    NativeInput,
    NativeLaunch,
    NativeResize,
    NativeSnapshot,
)
from toolkit.secdesk.registry import ToolManifest


class NativeControls(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.tool: ToolManifest | None = None
        self.sessions: dict[UUID, NativeSnapshot] = {}
        self.pending = ""
        self.dimensions: tuple[int, int] | None = None
        self.reading = False
        self.console_pending = ""
        layout = QVBoxLayout(self)
        layout.setSpacing(SPACE["sm"])
        layout.setContentsMargins(0, 0, 0, 0)
        actions = QHBoxLayout()
        self.gui = self.button("Launch native GUI", lambda: self.launch("gui"))
        self.terminal_button = self.button("Open in Terminal", lambda: self.launch("terminal"))
        self.stop_button = self.button("Close owned session", self.stop)
        self.stop_button.setProperty("role", "danger")
        for button in (self.gui, self.terminal_button, self.stop_button):
            actions.addWidget(button)
        layout.addLayout(actions)
        self.selection = QComboBox()
        self.selection.setAccessibleName("Workspace native sessions")
        self.selection.setToolTip("Select a session for this tool in the current workspace.")
        self.selection.currentIndexChanged.connect(self.select)
        layout.addWidget(self.selection)
        self.status = StatusBadge("No owned session")
        self.status.set_status("No owned session", "idle")
        layout.addWidget(self.status)
        self.terminal = NativeTerminalView()
        self.terminal.hide()
        self.terminal.setMinimumHeight(160)
        self.terminal.typed.connect(self.queue_input)
        self.terminal.resized.connect(self.queue_resize)
        layout.addWidget(self.terminal)
        self.audit_output = QPlainTextEdit()
        self.audit_output.setReadOnly(True)
        self.audit_output.setAccessibleName("Local launch audit")
        self.audit_output.setToolTip(
            "Latest 200 local launch records. Commands and output are not recorded."
        )
        self.audit_output.hide()
        layout.addWidget(self.button("Show local launch audit", self.audit))
        layout.addWidget(self.audit_output)
        self.vm.state_changed.connect(self.update_state)
        self.vm.action_error.connect(self.error)
        self.timer = QTimer(self)
        self.timer.setInterval(300)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        self.input_timer = QTimer(self)
        self.input_timer.setInterval(100)
        self.input_timer.timeout.connect(self.flush)
        self.input_timer.start()
        self.enable_launch()

    @staticmethod
    def button(text: str, action: Callable[[], None]) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(text)
        button.setToolTip(text)
        button.clicked.connect(action)
        return button

    def set_tool(self, tool: ToolManifest) -> None:
        self.tool = tool
        self.console_pending = ""
        self.pending = ""
        self.dimensions = None
        self.terminal.clear()
        self.audit_output.hide()
        self.terminal_button.setText(
            "Open in Terminal (recommended)" if tool.terminal_recommended else "Open in Terminal"
        )
        self.enable_launch()
        self.rebuild_selection()
        if self.vm.workspace_id is not None:
            self.vm.get(
                "secdesk-sessions",
                f"/api/v1/secdesk/sessions?workspace_id={self.vm.workspace_id}",
                RootModel[list[NativeSnapshot]],
            )

    def enable_launch(self) -> None:
        self.gui.setEnabled(bool(self.vm.workspace_id and self.tool and self.tool.native_gui))
        self.terminal_button.setEnabled(
            bool(self.vm.workspace_id and self.tool and self.tool.has_terminal)
        )
        self.gui.setToolTip(
            "Launch the installed native GUI."
            if self.tool and self.tool.native_gui
            else "This tool uses a vendor web console or has no native GUI."
        )

    def current(self) -> NativeSnapshot | None:
        return self.sessions.get(self.selection.currentData())

    def launch(self, mode: str) -> None:
        if not self.tool or self.vm.workspace_id is None:
            return
        data = NativeLaunch.model_validate(
            {
                "workspace_id": self.vm.workspace_id,
                "tool_id": self.tool.id,
                "mode": mode,
            }
        )
        self.vm.invalidate("secdesk-sessions")
        self.status.set_status("Starting owned session", "running")
        self.vm.mutate("secdesk-launch", "POST", "/api/v1/secdesk/launch", NativeSnapshot, data)

    def select(self) -> None:
        self.pending = ""
        self.reading = False
        item = self.current()
        self.terminal.setEnabled(
            bool(item and item.status == "running" and item.mode == "terminal")
        )
        self.stop_button.setEnabled(bool(item and item.status in {"running", "failed"}))
        self.terminal.setPlainText(item.screen if item else "")
        self.terminal.setVisible(bool(item and item.mode == "terminal"))
        self.status.set_status(
            item.message or item.status if item else "No owned session",
            self.badge_state(item),
        )

    @staticmethod
    def badge_state(item: NativeSnapshot | None) -> str:
        if item is None:
            return "idle"
        return "done" if item.status in {"exited", "closed"} else item.status

    def poll(self) -> None:
        item = self.current()
        if item and item.status == "running" and not self.reading:
            self.reading = True
            self.vm.get(
                "secdesk-session",
                f"/api/v1/secdesk/session/{item.id}?workspace_id={item.workspace_id}",
                NativeSnapshot,
            )

    def queue_input(self, text: str) -> None:
        if len(self.pending) + len(text) <= 4096 and self.current():
            self.pending += text

    def queue_resize(self, rows: int, columns: int) -> None:
        self.dimensions = rows, columns

    def flush(self) -> None:
        item = self.current()
        if not item or item.status != "running" or item.mode != "terminal":
            self.pending = ""
            return
        if self.pending:
            text, self.pending = self.pending, ""
            self.vm.mutate(
                "secdesk-input",
                "POST",
                "/api/v1/secdesk/input",
                NativeSnapshot,
                NativeInput(id=item.id, workspace_id=item.workspace_id, text=SecretStr(text)),
            )
        if self.dimensions and self.dimensions != (item.rows, item.columns):
            rows, columns = self.dimensions
            self.dimensions = None
            self.vm.mutate(
                "secdesk-resize",
                "POST",
                "/api/v1/secdesk/resize",
                NativeSnapshot,
                NativeResize(
                    id=item.id, workspace_id=item.workspace_id, rows=rows, columns=columns
                ),
            )

    def stop(self) -> None:
        item = self.current()
        if item:
            self.pending = ""
            self.vm.mutate(
                "secdesk-close",
                "POST",
                "/api/v1/secdesk/close",
                NativeSnapshot,
                NativeHandle(id=item.id, workspace_id=item.workspace_id),
            )

    def audit(self) -> None:
        if self.vm.workspace_id:
            self.vm.get(
                "secdesk-audit",
                f"/api/v1/secdesk/audit?workspace_id={self.vm.workspace_id}",
                RootModel[list[NativeAudit]],
            )

    def update_state(self, key: str, value: object) -> None:
        if key == "workspace":
            self.console_pending = ""
            self.sessions.clear()
            self.selection.clear()
            self.pending = ""
            self.audit_output.clear()
            self.select()
            if self.tool:
                self.set_tool(self.tool)
        elif key == "secdesk-console" and isinstance(value, ActionResult):
            url, self.console_pending = self.console_pending, ""
            if url and value.status == "acknowledged":
                if QDesktopServices.openUrl(QUrl(url)):
                    self.status.set_status(
                        "Console opened; service and license status remain unknown", "unknown"
                    )
                else:
                    self.status.set_status(
                        "Browser could not open the console; retry explicitly", "failed"
                    )
        elif key == "secdesk-audit" and isinstance(value, RootModel):
            self.audit_output.setPlainText(
                "\n".join(
                    f"{row.created_at.isoformat()} {row.tool_id} {row.mode} " f"{row.event}"
                    for row in value.root
                    if isinstance(row, NativeAudit)
                )
                or "No local launches recorded."
            )
            self.audit_output.show()
        elif key == "secdesk-sessions" and isinstance(value, RootModel):
            # A GET started before a mutation must never remove or roll back its result.
            self.sessions = {
                row.id: row for row in value.root if isinstance(row, NativeSnapshot)
            } | self.sessions
            self.sessions = dict(list(self.sessions.items())[-100:])
            self.rebuild_selection()
        elif key.startswith("secdesk-") and isinstance(value, NativeSnapshot):
            self.sessions[value.id] = value
            if key == "secdesk-launch":
                self.vm.invalidate("secdesk-sessions")
                self.rebuild_selection(value.id)
            current = self.current()
            if current and current.id == value.id:
                self.reading = False
                if self.terminal.toPlainText() != value.screen:
                    self.terminal.setPlainText(value.screen)
                self.status.set_status(value.message or value.status, self.badge_state(value))
                self.terminal.setVisible(value.mode == "terminal")
                self.stop_button.setEnabled(value.status in {"running", "failed"})
                self.terminal.setEnabled(value.status == "running" and value.mode == "terminal")

    def rebuild_selection(self, selected: UUID | None = None) -> None:
        previous = selected or self.selection.currentData()
        self.selection.blockSignals(True)
        self.selection.clear()
        for item in self.sessions.values():
            if (
                self.tool
                and item.tool_id == self.tool.id
                and item.workspace_id == self.vm.workspace_id
            ):
                self.selection.addItem(f"{item.mode} {str(item.id)[:8]} · {item.status}", item.id)
        index = self.selection.findData(previous)
        self.selection.setCurrentIndex(max(0, index))
        self.selection.blockSignals(False)
        self.select()

    def error(self, key: str, message: str) -> None:
        if key.startswith("secdesk-"):
            self.reading = False
            self.pending = ""
            self.console_pending = ""
            self.status.set_status(message + "; no command was repeated", "failed")

    def open_console(self, url: str) -> None:
        if self.tool is None or self.vm.workspace_id is None:
            return
        self.console_pending = url
        self.vm.mutate(
            "secdesk-console",
            "POST",
            "/api/v1/secdesk/console",
            ActionResult,
            NativeLaunch(workspace_id=self.vm.workspace_id, tool_id=self.tool.id, mode="gui"),
        )
