"""Flat desktop dashboard; all service state arrives through the ViewModel."""

from PyQt6.QtCore import Qt, pyqtSlot
from PyQt6.QtGui import QCloseEvent
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.base_vm import BaseViewModel
from shared.schemas import HealthResponse


class MainWindow(QMainWindow):
    """Own navigation widgets and presentation, with no backend or HTTP dependency."""

    def __init__(self, view_model: BaseViewModel) -> None:
        super().__init__()
        self._vm = view_model
        self.setWindowTitle("Cybersecurity Fundamentals Toolkit")
        self.resize(1100, 740)
        central = QWidget()
        layout = QHBoxLayout(central)
        self.sidebar = QListWidget()
        self.sidebar.setMaximumWidth(250)
        self.sidebar.addItem("Dashboard")
        for title in ("Workspaces", "Modules", "Jobs", "Artifacts", "Settings"):
            item = QListWidgetItem(title)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)
            self.sidebar.addItem(item)
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
        self._vm.close()
        if event is not None:
            event.accept()
