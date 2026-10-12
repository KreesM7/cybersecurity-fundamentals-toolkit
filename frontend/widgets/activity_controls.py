"""Guided activity controls, separate from the existing terminal transport."""

from pathlib import Path
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.help_text import COPY
from frontend.widgets.presentation import StatusBadge, enhance
from shared.activity import RemoteItem
from shared.modules import ModuleLibrary

if TYPE_CHECKING:
    from frontend.views.activity import ActivityPanel


def build_activity(owner: "ActivityPanel") -> None:
    root = QVBoxLayout(owner)
    heading = QLabel("Sessions & Jobs")
    heading.setObjectName("pageTitle")
    root.addWidget(heading)
    owner.connection = StatusBadge("Connect in Settings. Local analysis jobs work offline.")
    root.addWidget(owner.connection)
    owner.tabs = QTabWidget()
    for name in ("Sessions", "Jobs", "Console"):
        page = QWidget()
        page.setLayout(QVBoxLayout())
        owner.tabs.addTab(page, name)
    root.addWidget(owner.tabs, 1)
    owner.tree = QTreeWidget()
    owner.tree.setHeaderLabels(["Kind", "ID", "Name / state", "Peer", "Ownership"])
    owner.tree.currentItemChanged.connect(owner.remember_selection)
    page_layout(owner.tabs, 0).addWidget(owner.tree)
    owner.activity_toolbar = QWidget()
    buttons = QHBoxLayout(owner.activity_toolbar)
    for title, callback in (
        ("Refresh", owner.refresh),
        ("Import into workspace", owner.claim),
        ("Stop selected", owner.stop),
        ("Open session terminal", owner.session_terminal),
    ):
        button = QPushButton(title)
        button.clicked.connect(callback)
        buttons.addWidget(button)
    root.addWidget(owner.activity_toolbar)
    console = page_layout(owner.tabs, 2)
    owner.guided_stops = []
    guided = QHBoxLayout()
    owner.context = QComboBox()
    owner.context.addItem("Choose a session or saved module", None)
    guided.addWidget(owner.context, 1)
    for title, callback in (
        ("Run / configure", lambda: guided_run(owner)),
        ("Back", lambda: owner.navigate_requested.emit("Modules")),
        ("Sessions", lambda: owner.tabs.setCurrentIndex(0)),
        ("Jobs", lambda: owner.tabs.setCurrentIndex(1)),
        ("Kill selected", lambda: guided_stop(owner)),
    ):
        button = QPushButton(title)
        button.clicked.connect(callback)
        guided.addWidget(button)
        if title == "Kill selected":
            owner.guided_stops.append(button)
            button.setEnabled(False)
    console.addLayout(guided)
    owner.output = QPlainTextEdit()
    owner.output.setReadOnly(True)
    owner.output.setMaximumBlockCount(10000)
    owner.output.setPlaceholderText(COPY["empty_console"])
    console.addWidget(owner.output)
    controls = QHBoxLayout()
    for title, callback in (
        ("Copy", lambda: copy_output(owner)),
        ("Clear", owner.output.clear),
        ("Save artifact…", lambda: save_output(owner)),
        ("Stop selected", lambda: guided_stop(owner)),
    ):
        button = QPushButton(title)
        button.clicked.connect(callback)
        if title == "Stop selected":
            owner.guided_stops.append(button)
            button.setEnabled(False)
        if title.startswith("Save"):
            button.setToolTip(COPY["artifact"])
        controls.addWidget(button)
    console.addLayout(controls)
    owner.advanced = QCheckBox("Advanced console")
    console.addWidget(owner.advanced)
    owner.raw_controls = QWidget()
    raw = QVBoxLayout(owner.raw_controls)
    warning = QLabel(COPY["advanced_warning"])
    warning.setWordWrap(True)
    raw.addWidget(warning)
    raw_buttons = QHBoxLayout()
    for title, callback in (
        ("Open console", owner.open_console),
        ("Close terminal view", owner.close_terminal),
        ("Redacted history", owner.history),
    ):
        button = QPushButton(title)
        button.clicked.connect(callback)
        raw_buttons.addWidget(button)
    raw.addLayout(raw_buttons)
    command_row = QHBoxLayout()
    owner.command = QLineEdit()
    owner.command.setMaxLength(65536)
    send = QPushButton("Send")
    send.clicked.connect(owner.send)
    owner.command.returnPressed.connect(owner.send)
    command_row.addWidget(owner.command)
    command_row.addWidget(send)
    raw.addLayout(command_row)
    console.addWidget(owner.raw_controls)
    owner.raw_controls.hide()
    owner.advanced.toggled.connect(owner.raw_controls.setVisible)
    owner.tabs.currentChanged.connect(lambda: filter_activity(owner))
    owner.context.currentIndexChanged.connect(lambda: select_context(owner))
    enhance(owner)


def filter_activity(owner: "ActivityPanel") -> None:
    index = owner.tabs.currentIndex()
    owner.activity_toolbar.setVisible(index < 2)
    if index < 2:
        page_layout(owner.tabs, index).addWidget(owner.tree)
        owner.tree.show()
        for row in range(owner.tree.topLevelItemCount()):
            item = owner.tree.topLevelItem(row)
            if item:
                value = item.data(0, Qt.ItemDataRole.UserRole)
                session = isinstance(value, RemoteItem) and value.kind == "session"
                item.setHidden(session != (index == 0))


def update_context(owner: "ActivityPanel", library: ModuleLibrary | None = None) -> None:
    if library is not None:
        owner.library = library
    selected = owner.context.currentData()
    owner.context.blockSignals(True)
    owner.context.clear()
    owner.context.addItem("Choose a session or saved module", None)
    if owner.snapshot:
        for item in owner.snapshot.items:
            if item.workspace_id == owner.vm.workspace_id:
                owner.context.addItem(
                    f"{item.kind} {item.remote_id} · {item.name}", (item.kind, item.remote_id)
                )
    for path in dict.fromkeys(owner.library.favorites + owner.library.recent):
        owner.context.addItem(path, ("module", path))
    index = owner.context.findData(selected)
    owner.context.setCurrentIndex(max(index, 0))
    owner.context.blockSignals(False)
    select_context(owner)


def select_context(owner: "ActivityPanel") -> None:
    selected = owner.context.currentData()
    match = None
    if selected and selected[0] in {"session", "job"}:
        for index in range(owner.tree.topLevelItemCount()):
            item = owner.tree.topLevelItem(index)
            if item and (item.text(0), item.text(1)) == tuple(selected):
                match = item
                break
    for button in owner.guided_stops:
        button.setEnabled(match is not None)
    if match is not None:
        owner.tree.setCurrentItem(match)


def guided_stop(owner: "ActivityPanel") -> None:
    select_context(owner)
    if owner.guided_stops and owner.guided_stops[0].isEnabled():
        owner.stop()


def guided_run(owner: "ActivityPanel") -> None:
    selected = owner.context.currentData()
    if selected and selected[0] == "session":
        select_context(owner)
        owner.session_terminal()
    else:
        owner.navigate_requested.emit("Modules")
        if selected and selected[0] == "module":
            owner.module_requested.emit(selected[1])


def copy_output(owner: "ActivityPanel") -> None:
    clipboard = QApplication.clipboard()
    if clipboard:
        clipboard.setText(owner.output.toPlainText())


def save_output(owner: "ActivityPanel") -> None:
    destination, _ = QFileDialog.getSaveFileName(
        owner, "Save redacted console artifact", "console.txt", "Text artifacts (*.txt)"
    )
    if destination:
        try:
            Path(destination).write_text(owner.output.toPlainText(), "utf-8")
            owner.connection.setText("Saved local text artifact.")
        except OSError:
            owner.connection.setText("Failed to save. Choose a writable destination and retry.")


def page_layout(tabs: QTabWidget, index: int) -> QVBoxLayout:
    page = tabs.widget(index)
    assert page is not None
    layout = page.layout()
    assert isinstance(layout, QVBoxLayout)
    return layout
