"""Manifest-driven education hub; external tools are never launched implicitly."""

from pydantic import RootModel
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.theme import SPACE
from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.presentation import StatusBadge
from toolkit.secdesk.registry import Check, ToolManifest, load_registry


class SecDeskPanel(QWidget):
    def __init__(self, view_model: AppViewModel) -> None:
        super().__init__()
        self.vm = view_model
        self.registry_failed = False
        try:
            self.tools = load_registry()
        except (OSError, ValueError):
            self.tools = []
            self.registry_failed = True
        self.checks: dict[str, Check] = {}
        self.current: ToolManifest | None = None
        layout = QVBoxLayout(self)
        layout.setSpacing(SPACE["md"])
        self.status = StatusBadge("Loading local environment checks")
        layout.addWidget(self.status)
        recheck = self.button("Recheck environment", "Check local executable presence only.")
        recheck.clicked.connect(self.refresh)
        layout.addWidget(recheck)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        grid_page = QWidget()
        grid = QGridLayout(grid_page)
        grid.setAlignment(Qt.AlignmentFlag.AlignTop)
        grid.setSpacing(SPACE["lg"])
        self.badges: dict[str, StatusBadge] = {}
        for index, tool in enumerate(self.tools):
            card = QWidget()
            card_layout = QVBoxLayout(card)
            card_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
            card_layout.addWidget(QLabel(tool.name))
            description = QLabel(tool.one_liner)
            description.setWordWrap(True)
            card_layout.addWidget(description)
            badge = StatusBadge("Loading")
            self.badges[tool.id] = badge
            card_layout.addWidget(badge)
            details = self.button("Open tool details", f"Read {tool.name} setup and documentation.")
            details.clicked.connect(lambda checked=False, selected=tool: self.show_tool(selected))
            card_layout.addWidget(details)
            grid.addWidget(card, index // 2, index % 2)
        self.stack.addWidget(grid_page)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        back = self.button("← Tools", "Return to the tool grid.")
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        detail_layout.addWidget(back)
        self.document = QPlainTextEdit()
        self.document.setReadOnly(True)
        self.document.setAccessibleName("Tool overview, setup, commands, examples and errors")
        self.document.setToolTip(
            "Vendor-sourced guidance; unverified output is explicitly identified."
        )
        detail_layout.addWidget(self.document, 1)
        links = QHBoxLayout()
        for text, attribute in (
            ("Official documentation", "docs_link"),
            ("Official install page", "install_link"),
        ):
            button = self.button(
                text, "Open the vendor HTTPS page in your browser; no installation runs."
            )
            button.clicked.connect(lambda checked=False, key=attribute: self.open_link(key))
            links.addWidget(button)
        detail_layout.addLayout(links)
        self.stack.addWidget(detail)
        self.vm.state_changed.connect(self.update_state)
        self.vm.action_error.connect(self.show_error)
        if self.registry_failed:
            self.status.set_status(
                "Tool manifests unavailable; restore installation and restart", "failed"
            )
        else:
            self.refresh()

    @staticmethod
    def button(text: str, description: str) -> QPushButton:
        button = QPushButton(text)
        button.setAccessibleName(text)
        button.setToolTip(description)
        return button

    def refresh(self) -> None:
        self.status.setText("Loading local environment checks")
        self.vm.get("secdesk-doctor", "/api/v1/secdesk/doctor", RootModel[list[Check]])

    def update_state(self, key: str, value: object) -> None:
        if key != "secdesk-doctor" or not isinstance(value, RootModel):
            return
        for check in value.root:
            if isinstance(check, Check):
                self.checks[check.tool_id] = check
                if check.tool_id in self.badges:
                    text = "Not Installed" if check.status == "not_installed" else "Needs setup"
                    self.badges[check.tool_id].set_status(text, "failed")
                    self.badges[check.tool_id].setToolTip(check.reason)
        self.status.setText("Completed local checks; no tools, services or captures started")
        if self.current:
            self.show_tool(self.current)

    def show_error(self, key: str, message: str) -> None:
        if key == "secdesk-doctor":
            self.status.setText("Failed environment check: " + message)

    def show_tool(self, tool: ToolManifest) -> None:
        self.current = tool
        check = self.checks.get(tool.id)
        setup = check.reason + "\n" + check.remediation if check else "Environment check pending."
        commands = "\n".join(
            f"{item.cmd}\n  {item.explain} [{item.verification}; not locally tested]"
            for item in tool.commands
        )
        errors = (
            "\n".join(
                f"{item.pattern}: {item.cause}\n{item.fix}\n{item.doc_link}" for item in tool.errors
            )
            or "No verified native error patterns recorded yet."
        )
        self.document.setPlainText(
            f"{tool.name}\n\n1. Overview\n{tool.overview}\n\n2. Setup\n{setup}\n"
            + "\n".join(tool.setup_steps)
            + f"\n\n3. Command cheatsheet\n{commands}\n\n4. Example: successful run\n"
            + (
                tool.example_success.output
                if tool.example_success.verified
                else "Unverified: no real run captured."
            )
            + "\n\n5. Example: failed run\n"
            + (
                tool.example_failure.output
                if tool.example_failure.verified
                else "Unverified: no native failure captured."
            )
            + f"\n\n6. Error dictionary\n{errors}\n\n7. Launch\n"
            + "Managed launching and embedded terminal are not available in this initial milestone."
        )
        self.stack.setCurrentIndex(1)

    def open_link(self, attribute: str) -> None:
        if self.current:
            url = getattr(self.current, attribute)
            ToolManifest.validate_link(url)
            QDesktopServices.openUrl(QUrl(url))
