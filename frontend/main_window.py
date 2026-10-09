"""Flat desktop dashboard; all service state arrives through the ViewModel."""

from PyQt6.QtCore import Qt, QTimer, pyqtSlot
from PyQt6.QtGui import QCloseEvent, QKeySequence, QShortcut
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from frontend.viewmodels.base_vm import BaseViewModel
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.activity import ActivityPanel
from frontend.views.desktop import DesktopControls
from frontend.views.modules import ModuleBrowser
from frontend.views.payloads import PayloadPanel
from frontend.views.reports import ReportsPanel
from frontend.views.tools import PANELS, create_panel
from frontend.views.vault import VaultPanel
from frontend.views.workspaces import ArtifactsPanel, TargetsPanel, WorkspacePanel
from shared.framework import ShutdownCheck
from shared.schemas import HealthResponse
from shared.tools import ToolView


class MainWindow(QMainWindow):
    """Own navigation widgets and presentation, with no backend or HTTP dependency."""

    def __init__(self, view_model: BaseViewModel) -> None:
        super().__init__()
        self._vm = view_model
        self._closing = False
        self._checking_close = False
        self.setWindowTitle("Cybersecurity Fundamentals Toolkit")
        self.resize(1100, 740)
        central = QWidget()
        layout = QHBoxLayout(central)
        self.sidebar = QListWidget()
        self.sidebar.setMinimumWidth(230)
        self.sidebar.setMaximumWidth(250)
        self.sidebar.addItem("Dashboard")
        self.stack = QStackedWidget()
        dashboard = QWidget()
        content = QVBoxLayout(dashboard)
        page_title = QLabel("Toolkit dashboard")
        page_title.setObjectName("pageTitle")
        self.health_label = QLabel("Backend health has not been checked.")
        self.health_label.setWordWrap(True)
        self.error_label = QLabel("")
        self.error_label.setWordWrap(True)
        refresh = QPushButton("Refresh health")
        refresh.clicked.connect(view_model.refresh_health)
        content.addWidget(page_title)
        content.addWidget(self.health_label)
        content.addWidget(self.error_label)
        self.readiness_label = QLabel("Tool readiness has not been checked.")
        self.readiness_label.setWordWrap(True)
        content.addWidget(self.readiness_label)
        content.addWidget(refresh)
        content.addStretch()
        self.stack.addWidget(dashboard)
        self.sidebar.currentItemChanged.connect(self._navigate)
        self.sidebar.setCurrentRow(0)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        view_model.health_changed.connect(self._show_health)
        view_model.error_changed.connect(self.error_label.setText)
        self.panels: dict[str, QWidget] = {}
        if isinstance(view_model, ToolsViewModel):
            refresh.clicked.connect(view_model.refresh_tools)
            for tool_id, title in PANELS:
                panel = create_panel(tool_id, view_model)
                self.panels[tool_id] = panel
                self.register_view(title, panel)
            view_model.tools_changed.connect(self._show_tools)
        if isinstance(view_model, AppViewModel):
            desktop_controls = DesktopControls(view_model)
            content.insertWidget(1, desktop_controls)
            workspace_panel = WorkspacePanel(view_model)
            activity_panel = ActivityPanel(view_model)
            self.register_view("Workspaces", workspace_panel)
            self.register_view("Targets", TargetsPanel(view_model))
            self.register_view("Modules", ModuleBrowser(view_model))
            self.register_view("Payloads", PayloadPanel(view_model))
            self.register_view("Sessions / Jobs / Console", activity_panel)
            self.register_view("Artifacts", ArtifactsPanel(view_model))
            self.register_view("Vault", VaultPanel(view_model))
            self.register_view("Reports", ReportsPanel(view_model))
            self.register_view("Settings", desktop_controls.settings_panel)
            for keys, callback in (
                ("Ctrl+K", self.command_palette),
                ("Ctrl+T", lambda: self.navigate_title("Modules")),
                ("Ctrl+L", lambda: self.navigate_title("Sessions / Jobs / Console")),
                ("Ctrl+S", workspace_panel.save_notes),
                ("F5", activity_panel.refresh),
            ):
                shortcut = QShortcut(QKeySequence(keys), self)
                shortcut.activated.connect(callback)
            view_model.state_changed.connect(self._shutdown_result)
            view_model.action_error.connect(self._shutdown_error)
            view_model.watch_events("/ws/events")

    def navigate_title(self, title: str) -> None:
        for index in range(self.sidebar.count()):
            item = self.sidebar.item(index)
            if item and item.text() == title:
                self.sidebar.setCurrentRow(index)
                break

    def command_palette(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("Go to page")
        dialog.resize(420, 420)
        layout = QVBoxLayout(dialog)
        query = QLineEdit()
        query.setPlaceholderText("Type a page name…")
        choices = QListWidget()
        layout.addWidget(query)
        layout.addWidget(choices)
        for index in range(self.sidebar.count()):
            item = self.sidebar.item(index)
            if item:
                choices.addItem(item.text())

        def filter_pages(value: str) -> None:
            for index in range(choices.count()):
                item = choices.item(index)
                if item:
                    item.setHidden(value.casefold() not in item.text().casefold())
            choices.setCurrentItem(
                next(
                    (
                        choices.item(i)
                        for i in range(choices.count())
                        if (candidate := choices.item(i)) is not None and not candidate.isHidden()
                    ),
                    None,
                )
            )

        def accept() -> None:
            item = choices.currentItem()
            if item:
                self.navigate_title(item.text())
                dialog.accept()

        query.textChanged.connect(filter_pages)
        query.returnPressed.connect(accept)
        choices.itemActivated.connect(accept)
        choices.setCurrentRow(0)
        query.setFocus()
        dialog.exec()

    def _show_tools(self, values: object) -> None:
        if isinstance(values, list):
            self.readiness_label.setText(
                "\n".join(
                    f"{value.title}: {value.reason or 'Ready'}"
                    for value in values
                    if isinstance(value, ToolView)
                )
            )

    @pyqtSlot(object)
    def _show_health(self, health: object) -> None:
        if isinstance(health, HealthResponse):
            self.health_label.setText(
                f"Backend {health.status} · Version {health.version}\nInstance {health.instance_id}"
            )
            self.error_label.clear()

    def register_view(self, title: str, view: QWidget) -> None:
        """Add a migrated panel when its implementation is ready."""
        index = self.stack.addWidget(view)
        item = QListWidgetItem(title)
        item.setData(Qt.ItemDataRole.UserRole, index)
        self.sidebar.addItem(item)

    @pyqtSlot(QListWidgetItem, QListWidgetItem)
    def _navigate(self, current: QListWidgetItem | None, previous: QListWidgetItem | None) -> None:
        if current is not None:
            index = current.data(Qt.ItemDataRole.UserRole)
            self.stack.setCurrentIndex(index if isinstance(index, int) else 0)

    def closeEvent(self, event: QCloseEvent | None) -> None:  # noqa: N802 - Qt override
        if isinstance(self._vm, AppViewModel) and not self._closing:
            if event is not None:
                event.ignore()
            if not self._checking_close:
                self._checking_close = True
                self._vm.get("shutdown-check", "/api/v1/connection/shutdown-check", ShutdownCheck)
            return
        for timer in self.findChildren(QTimer):
            timer.stop()
        self._vm.close()
        if event is not None:
            event.accept()

    def _shutdown_result(self, key: str, value: object) -> None:
        if key == "shutdown-check" and isinstance(value, ShutdownCheck):
            self._checking_close = False
            if value.confirmation_required and not self._confirm_shutdown():
                return
            self._closing = True
            self.close()

    def _confirm_shutdown(self) -> bool:
        return (
            QMessageBox.question(
                self,
                "Stop owned activity?",
                "Closing will stop active or uncertain sessions and jobs in the app's "
                "owned Metasploit console. Close now?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        )

    def _shutdown_error(self, key: str, message: str) -> None:
        if key == "shutdown-check":
            self._checking_close = False
            if self._confirm_shutdown():
                self._closing = True
                self.close()
