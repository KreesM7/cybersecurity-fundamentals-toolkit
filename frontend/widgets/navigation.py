"""Grouped, collapsible navigation with Settings pinned outside the scrolling list."""

from collections.abc import Callable

from PyQt6.QtCore import QEvent, QSize, Qt
from PyQt6.QtWidgets import QListWidget, QListWidgetItem, QPushButton, QVBoxLayout, QWidget

from frontend.help_text import COPY
from frontend.icons import line_icon
from frontend.theme import SIZE, SPACE
from frontend.views.tools import PANELS

TITLE_ROLE = Qt.ItemDataRole.UserRole + 1
ICON_ROLE = Qt.ItemDataRole.UserRole + 2
GROUPS = (
    ("WORKSPACE", ("Dashboard", "Workspaces", "Targets")),
    ("OFFENSIVE", ("Modules", "Payloads", "Sessions & Jobs")),
    ("FUNDAMENTALS", tuple(title for _, title in PANELS)),
    ("DATA", ("Artifacts", "Reports", "Vault")),
)
ICONS = dict(
    zip(
        (
            "Dashboard",
            "Workspaces",
            "Targets",
            "Modules",
            "Payloads",
            "Sessions & Jobs",
            "Caesar Cipher",
            "Password Strength",
            "Network Scanner",
            "DoS Pattern Detector",
            "SQL Injection Checker",
            "Network Anomaly Detector",
            "File Type Identifier",
            "Artifacts",
            "Reports",
            "Vault",
            "Settings",
        ),
        (
            "dashboard",
            "folder",
            "target",
            "modules",
            "payload",
            "terminal",
            "cipher",
            "lock",
            "network",
            "activity",
            "database",
            "activity",
            "file",
            "folder",
            "file",
            "lock",
            "settings",
        ),
        strict=True,
    )
)


class Navigation(QWidget):
    def __init__(self, sidebar: QListWidget, navigate: Callable[[str], None]) -> None:
        super().__init__()
        self.sidebar = sidebar
        self.collapsed = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACE["xs"], SPACE["xs"], SPACE["xs"], SPACE["xs"])
        self.toggle = QPushButton("Collapse navigation")
        self.toggle.setAccessibleName("Collapse or expand navigation")
        self.toggle.setToolTip(COPY["collapse"])
        self.toggle.clicked.connect(self.collapse)
        layout.addWidget(self.toggle)
        layout.addWidget(sidebar, 1)
        self.settings = QPushButton("Settings")
        self.settings.setAccessibleName("Settings")
        self.settings.setToolTip(COPY["settings"])
        self.settings.clicked.connect(lambda: navigate("Settings"))
        layout.addWidget(self.settings)
        self.setFixedWidth(SIZE["sidebar"])
        sidebar.setMinimumWidth(0)
        sidebar.setAccessibleName("Pages")
        sidebar.setIconSize(QSize(SIZE["icon"], SIZE["icon"]))
        self.icons()

    def populate(self, pages: dict[str, int]) -> None:
        self.sidebar.clear()
        for group, titles in GROUPS:
            present = [title for title in titles if title in pages]
            if not present:
                continue
            label = QListWidgetItem(group)
            label.setFlags(Qt.ItemFlag.NoItemFlags)
            self.sidebar.addItem(label)
            for title in present:
                item = QListWidgetItem(title)
                item.setData(Qt.ItemDataRole.UserRole, pages[title])
                item.setData(TITLE_ROLE, title)
                item.setData(ICON_ROLE, ICONS[title])
                item.setToolTip(title)
                self.sidebar.addItem(item)
        self.settings.setVisible("Settings" in pages)
        self.icons()

    def icons(self) -> None:
        if not hasattr(self, "toggle"):
            return
        self.toggle.setIcon(line_icon("collapse"))
        self.settings.setIcon(line_icon("settings"))
        for index in range(self.sidebar.count()):
            item = self.sidebar.item(index)
            if item and item.data(ICON_ROLE):
                item.setIcon(line_icon(item.data(ICON_ROLE)))

    def collapse(self) -> None:
        self.collapsed = not self.collapsed
        self.setFixedWidth(SIZE["collapsed"] if self.collapsed else SIZE["sidebar"])
        self.toggle.setText("" if self.collapsed else "Collapse navigation")
        self.settings.setText("" if self.collapsed else "Settings")
        for index in range(self.sidebar.count()):
            item = self.sidebar.item(index)
            if not item:
                continue
            title = item.data(TITLE_ROLE)
            if title:
                item.setText("" if self.collapsed else title)
            else:
                item.setHidden(self.collapsed)

    def changeEvent(self, event: QEvent | None) -> None:  # noqa: N802
        if event and event.type() == QEvent.Type.PaletteChange:
            self.icons()
        super().changeEvent(event)
