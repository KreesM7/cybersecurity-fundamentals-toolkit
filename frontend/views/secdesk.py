"""Manifest-driven education hub; external tools are never launched implicitly."""

from pydantic import RootModel
from PyQt6.QtCore import Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.theme import SPACE
from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.native_controls import NativeControls
from frontend.widgets.presentation import StatusBadge
from frontend.widgets.secdesk_findings import FindingsPanel
from toolkit.secdesk.registry import Check, Guide, ToolManifest, load_guides, load_registry


class SecDeskPanel(QWidget):
    navigate_requested = pyqtSignal(str)

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
        self.current: ToolManifest | Guide | None = None
        self.guides: list[Guide] = []
        try:
            self.guides = load_guides()
        except (OSError, ValueError):
            self.registry_failed = True
        layout = QVBoxLayout(self)
        layout.setSpacing(SPACE["md"])
        self.status = StatusBadge("Loading local environment checks")
        layout.addWidget(self.status)
        recheck = self.button("Recheck environment", "Check local executable presence only.")
        recheck.clicked.connect(self.refresh)
        layout.addWidget(recheck)
        sections = QHBoxLayout()
        for guide in self.guides:
            section = self.button(guide.title, "Read this dedicated educational section.")
            section.clicked.connect(lambda checked=False, selected=guide: self.show_guide(selected))
            sections.addWidget(section)
        findings_button = self.button(
            "Workspace findings", "Import explicit findings; export summaries from Reports."
        )
        findings_button.clicked.connect(self.show_findings)
        sections.addWidget(findings_button)
        layout.addLayout(sections)
        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.checklist = QTreeWidget()
        self.checklist.setHeaderLabels(["Startup check", "State", "Reason"])
        self.checklist.setMaximumHeight(180)
        self.checklist.setMinimumHeight(120)
        self.checklist.setAccessibleName("Visible local startup checklist")
        self.checklist.setToolTip(
            "Activate a row to read Setup. No tools, services or devices are started."
        )
        self.checklist.itemActivated.connect(self.check_setup)
        layout.insertWidget(1, self.checklist)
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
            if tool.license:
                license_badge = StatusBadge()
                license_badge.set_status("License: Not detected", "unknown")
                card_layout.addWidget(license_badge)
            details = self.button("Open tool details", f"Read {tool.name} setup and documentation.")
            details.clicked.connect(lambda checked=False, selected=tool: self.show_tool(selected))
            card_layout.addWidget(details)
            actions = QHBoxLayout()
            if tool.has_gui:
                gui_link = self.button(
                    "Open GUI panel", "Read setup and authorize GUI or console launch."
                )
                gui_link.clicked.connect(
                    lambda checked=False, selected=tool: self.show_tool(selected)
                )
                actions.addWidget(gui_link)
            if tool.has_terminal:
                text = (
                    "Open in Terminal (recommended)"
                    if tool.terminal_recommended
                    else "Open in Terminal"
                )
                terminal_link = self.button(
                    text, "Open documentation and explicit terminal launch controls."
                )
                terminal_link.clicked.connect(
                    lambda checked=False, selected=tool: self.show_tool(selected)
                )
                actions.addWidget(terminal_link)
            card_layout.addLayout(actions)
            grid.addWidget(card, index // 2, index % 2)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(grid_page)
        self.stack.addWidget(scroll)
        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        back = self.button("← Tools", "Return to the tool grid.")
        back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        detail_layout.addWidget(back)
        self.embedded_links = QHBoxLayout()
        detail_layout.addLayout(self.embedded_links)
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
        self.console_url = QLineEdit()
        self.console_url.setAccessibleName("Vendor HTTPS console URL")
        self.console_url.setPlaceholderText("Enter your vendor HTTPS console URL")
        self.console_url.setToolTip(
            "Explicit navigation only; no service health or license is assumed."
        )
        detail_layout.addWidget(self.console_url)
        self.console_button = self.button(
            "Open configured web console",
            "Open your HTTPS console in the browser after launch acknowledgment.",
        )
        self.console_button.clicked.connect(self.open_console)
        detail_layout.addWidget(self.console_button)
        self.usb_button = self.button(
            "Check USB ports", "Read local port metadata; no device connection opens."
        )
        self.usb_button.clicked.connect(self.check_usb)
        detail_layout.addWidget(self.usb_button)
        self.native_controls = NativeControls(self.vm)
        detail_layout.addWidget(self.native_controls)
        self.stack.addWidget(detail)
        findings_page = QWidget()
        findings_layout = QVBoxLayout(findings_page)
        tools_button = self.button("← Tools", "Return to the tool grid.")
        tools_button.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        findings_layout.addWidget(tools_button)
        self.findings = FindingsPanel(self.vm)
        findings_layout.addWidget(self.findings, 1)
        self.stack.addWidget(findings_page)
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
        self.checklist.clear()
        self.vm.get("secdesk-doctor", "/api/v1/secdesk/doctor", RootModel[list[Check]])
        self.vm.get(
            "secdesk-prerequisites", "/api/v1/secdesk/prerequisites", RootModel[list[Check]]
        )

    def update_state(self, key: str, value: object) -> None:
        if key == "secdesk-usb" and isinstance(value, RootModel):
            self.document.appendPlainText(
                "\nLocal USB-serial metadata (device identity remains unknown):"
            )
            for port in value.root:
                self.document.appendPlainText(
                    f"{port.device} VID={port.vendor_id} PID={port.product_id} {port.description}"
                )
            if not value.root:
                self.document.appendPlainText("No serial ports detected. No device was opened.")
            return
        if key not in {"secdesk-doctor", "secdesk-prerequisites"} or not isinstance(
            value, RootModel
        ):
            return
        for check in value.root:
            if isinstance(check, Check):
                self.checks[check.tool_id] = check
                row = QTreeWidgetItem([check.tool_id, check.status.replace("_", " "), check.reason])
                row.setData(0, Qt.ItemDataRole.UserRole, check.setup_tool_id or check.tool_id)
                row.setToolTip(2, check.reason + " " + check.remediation)
                self.checklist.addTopLevelItem(row)
                if check.tool_id in self.badges:
                    text = "Not Installed" if check.status == "not_installed" else "Needs setup"
                    self.badges[check.tool_id].set_status(text, "failed")
                    self.badges[check.tool_id].setToolTip(check.reason)
        self.status.setText("Completed local checks; no tools, services or captures started")
        if isinstance(self.current, ToolManifest):
            self.show_tool(self.current)

    def show_error(self, key: str, message: str) -> None:
        if key in {"secdesk-doctor", "secdesk-usb"}:
            self.status.set_status("Check failed: " + message, "failed")

    def show_tool(self, tool: ToolManifest) -> None:
        while self.embedded_links.count():
            item = self.embedded_links.takeAt(0)
            widget = item.widget() if item else None
            if widget:
                widget.deleteLater()
        for page in tool.embedded_pages:
            link = self.button(
                "Open in-app " + page, "Use the existing authenticated workspace panel."
            )
            link.clicked.connect(
                lambda checked=False, title=page: self.navigate_requested.emit(title)
            )
            self.embedded_links.addWidget(link)
        self.current = tool
        self.native_controls.show()
        self.console_url.setVisible(tool.console)
        self.console_button.setVisible(tool.console)
        self.usb_button.hide()
        check = self.checks.get(tool.id)
        setup = check.reason + "\n" + check.remediation if check else "Environment check pending."
        setup += "\nServices: " + (", ".join(tool.required_services) or "None declared")
        setup += "\nPermissions: " + ("; ".join(tool.required_permissions) or "Unknown")
        commands = (
            "\n".join(
                f"{item.cmd}\n  {item.explain} [{item.verification}; not locally tested]"
                for item in tool.commands
            )
            or "CLI commands remain unverified; consult the vendor web console and documentation."
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
            + "Launch explicitly below after acknowledging ownership. "
            + "Terminals use the workspace working directory and tool PATH. "
            + "No command runs automatically."
        )
        self.native_controls.set_tool(tool)
        self.stack.setCurrentIndex(1)

    def check_setup(self, item: QTreeWidgetItem, column: int) -> None:
        identifier = item.data(0, Qt.ItemDataRole.UserRole)
        tool = next((tool for tool in self.tools if tool.id == identifier), None)
        if tool:
            self.show_tool(tool)
        elif identifier == "Device companion":
            guide = next((guide for guide in self.guides if guide.detect_usb), None)
            if guide:
                self.show_guide(guide)

    def show_findings(self) -> None:
        self.findings.refresh()
        self.stack.setCurrentIndex(2)

    def show_guide(self, guide: Guide) -> None:
        while self.embedded_links.count():
            item = self.embedded_links.takeAt(0)
            widget = item.widget() if item else None
            if widget:
                widget.deleteLater()
        self.current = guide
        self.document.setPlainText(guide.title + "\n\n" + guide.text)
        self.native_controls.hide()
        self.console_url.hide()
        self.console_button.hide()
        self.usb_button.setVisible(guide.detect_usb)
        self.stack.setCurrentIndex(1)

    def check_usb(self) -> None:
        from toolkit.secdesk.companion import SerialPort

        self.vm.get("secdesk-usb", "/api/v1/secdesk/companion/ports", RootModel[list[SerialPort]])

    def open_console(self) -> None:
        if not isinstance(self.current, ToolManifest) or not self.current.console:
            return
        if not self.native_controls.consent.isChecked():
            self.status.set_status("Acknowledge ownership before opening a console", "failed")
            return
        try:
            url = ToolManifest.validate_link(self.console_url.text().strip())
        except ValueError:
            self.status.set_status("Enter a credential-free HTTPS console URL", "failed")
            return
        self.native_controls.open_console(url)

    def open_link(self, attribute: str) -> None:
        if self.current:
            url = getattr(self.current, attribute)
            ToolManifest.validate_link(url)
            QDesktopServices.openUrl(QUrl(url))
