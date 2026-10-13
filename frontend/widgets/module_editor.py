"""Three-step module presentation; requests remain in ModuleBrowser/ViewModel."""

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from backend.redaction import Redactor
from frontend.help_text import COPY, option_help
from frontend.theme import SIZE
from frontend.widgets.presentation import (
    LoadingSkeleton,
    StatusBadge,
    enhance,
    explain,
    guide_tabs,
    help_button,
)
from shared.modules import OptionSpec

if TYPE_CHECKING:
    from frontend.views.modules import ModuleBrowser


def build_editor(owner: "ModuleBrowser") -> None:
    from PyQt6.QtWidgets import QTreeWidget

    root = QVBoxLayout(owner)
    heading = QLabel("Metasploit modules")
    heading.setObjectName("pageTitle")
    root.addWidget(heading)
    split = QSplitter()
    saved = QWidget()
    side = QVBoxLayout(saved)
    side.addWidget(QLabel("Favorites / recent"))
    owner.saved = QComboBox()
    owner.saved.addItem("Select saved module", "")
    side.addWidget(owner.saved)
    owner.saved_list = QListWidget()
    side.addWidget(owner.saved_list)
    owner.favorite = QCheckBox("Favorite selected module")
    owner.favorite.setEnabled(False)
    side.addWidget(owner.favorite)
    split.addWidget(saved)
    owner.steps = QTabWidget()
    for name in ("1 · Find", "2 · Configure", "3 · Review & Run"):
        page = QWidget()
        page.setLayout(QVBoxLayout())
        owner.steps.addTab(page, name)
    find = page_layout(owner.steps, 0)
    filters = QHBoxLayout()
    owner.query = QLineEdit()
    owner.kind, owner.rank, owner.platform = QComboBox(), QComboBox(), QComboBox()
    owner.kind.addItems(
        ["All types", "auxiliary", "exploit", "post", "payload", "encoder", "nop", "evasion"]
    )
    owner.rank.addItems(
        ["All ranks", "manual", "low", "average", "normal", "good", "great", "excellent"]
    )
    owner.platform.addItems(
        ["All platforms", "windows", "linux", "unix", "multi", "osx", "android", "java", "php"]
    )
    owner.platform.setEditable(True)
    search = QPushButton("Search")
    for widget in (owner.query, owner.kind, owner.rank, owner.platform, search):
        filters.addWidget(widget)
    find.addLayout(filters)
    owner.tree = QTreeWidget()
    owner.tree.setHeaderLabels(["Module", "Rank"])
    find.addWidget(owner.tree)
    configure = page_layout(owner.steps, 1)
    owner.title = QLabel("Select a module in Find.")
    owner.title.setWordWrap(True)
    configure.addWidget(owner.title)
    owner.description = QPlainTextEdit()
    owner.description.setReadOnly(True)
    owner.description.setMaximumHeight(SIZE["description"])
    configure.addWidget(owner.description)
    owner.payload = QComboBox()
    owner.payload.addItem("Payload (when applicable)", "")
    configure.addWidget(owner.payload)
    owner.advanced = QCheckBox("Show advanced options")
    configure.addWidget(owner.advanced)
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    form_widget = QWidget()
    owner.form = QFormLayout(form_widget)
    scroll.setWidget(form_widget)
    configure.addWidget(scroll)
    owner.target = QComboBox()
    targets = QHBoxLayout()
    refresh, transfer = QPushButton("Refresh targets"), QPushButton("Use as RHOSTS")
    for widget in (owner.target, refresh, transfer):
        targets.addWidget(widget)
    configure.addLayout(targets)
    next_step = QPushButton("Review configuration")
    next_step.clicked.connect(lambda: owner.steps.setCurrentIndex(2))
    configure.addWidget(next_step)
    review = page_layout(owner.steps, 2)
    review.addWidget(QLabel(COPY["review"]))
    owner.summary = QPlainTextEdit()
    owner.summary.setReadOnly(True)
    review.addWidget(owner.summary)
    owner.run = QPushButton("Run selected module")
    owner.run.setEnabled(False)
    review.addWidget(owner.run)
    split.addWidget(owner.steps)
    split.setSizes([SIZE["side_list"], SIZE["window_w"] - SIZE["side_list"]])
    root.addWidget(split, 1)
    owner.output = QPlainTextEdit()
    owner.output.setReadOnly(True)
    owner.output.setMaximumBlockCount(10000)
    owner.output.setMaximumHeight(SIZE["output"])
    root.addWidget(owner.output)
    owner.status_badge = StatusBadge(
        "Choose a module. Connect in Settings if the catalog is unavailable."
    )
    root.addWidget(owner.status_badge)
    owner.loading = LoadingSkeleton()
    root.addWidget(owner.loading)
    search.clicked.connect(owner.search)
    owner.query.returnPressed.connect(owner.search)
    owner.tree.currentItemChanged.connect(owner.select)
    owner.favorite.toggled.connect(owner.set_favorite)
    owner.saved.activated.connect(owner.select_saved)
    owner.saved_list.currentItemChanged.connect(
        lambda item, previous: (
            owner.choose_module(item.data(Qt.ItemDataRole.UserRole)) if item else None
        )
    )
    owner.payload.activated.connect(owner.select_payload)
    refresh.clicked.connect(owner.vm.targets)
    transfer.clicked.connect(owner.transfer)
    owner.run.clicked.connect(owner.launch)
    owner.advanced.toggled.connect(owner.validate)
    owner.steps.currentChanged.connect(owner.validate)
    guide_tabs(owner, "modules", owner.try_example)


def render_options(owner: "ModuleBrowser", specs: list[OptionSpec], append: bool) -> None:
    if not append:
        while owner.form.rowCount():
            owner.form.removeRow(0)
        owner.fields.clear()
        owner.option_specs.clear()
        owner.option_rows.clear()
    for spec in specs:
        if spec.name in owner.fields:
            continue
        widget: QWidget
        if spec.kind == "bool":
            widget = QCheckBox()
            widget.setChecked(spec.default is True)
            widget.toggled.connect(owner.validate)
        elif spec.choices:
            widget = QComboBox()
            widget.addItems(spec.choices)
            if spec.default is not None:
                widget.setCurrentText(str(spec.default))
            widget.currentTextChanged.connect(owner.validate)
        else:
            widget = QLineEdit("" if spec.default is None else str(spec.default))
            widget.setMaxLength(4096)
            if spec.secret:
                widget.setEchoMode(QLineEdit.EchoMode.Password)
            widget.textChanged.connect(owner.validate)
        explain(widget, option_help(spec))
        container = QWidget()
        row = QVBoxLayout(container)
        input_row = QHBoxLayout()
        input_row.addWidget(widget)
        input_row.addWidget(help_button(widget))
        row.addLayout(input_row)
        error = QLabel()
        error.setProperty("role", "validation")
        row.addWidget(error)
        owner.form.addRow(
            spec.name + (" · Required" if spec.required else " · Optional"), container
        )
        owner.fields[spec.name] = widget
        owner.option_specs[spec.name] = spec
        owner.option_rows[spec.name] = (container, error)
    enhance(owner)
    validate_options(owner)


def validate_options(owner: "ModuleBrowser") -> bool:
    valid = owner.detail is not None
    summary = [owner.detail.path if owner.detail else "Select a module."]
    for name, widget in owner.fields.items():
        spec = owner.option_specs[name]
        value = (
            str(widget.isChecked())
            if isinstance(widget, QCheckBox)
            else (
                widget.currentText()
                if isinstance(widget, QComboBox)
                else widget.text() if isinstance(widget, QLineEdit) else ""
            )
        )
        message = COPY["required"] if spec.required and not value.strip() else ""
        if value.strip() and spec.kind in {"integer", "int", "float"}:
            try:
                float(value) if spec.kind == "float" else int(value)
            except ValueError:
                message = COPY["number"]
        container, error = owner.option_rows[name]
        error.setText(message)
        error.setVisible(bool(message))
        owner.form.setRowVisible(container, spec.required or owner.advanced.isChecked())
        valid = valid and not message
        if value:
            summary.append(name + ": " + ("[hidden]" if spec.secret else Redactor().text(value)))
    if owner.payload.currentData():
        summary.append("PAYLOAD: " + str(owner.payload.currentData()))
    owner.summary.setPlainText("\n".join(summary))
    allowed = bool(
        owner.detail
        and owner.detail.path.split("/", 1)[0] in {"auxiliary", "exploit", "post", "evasion"}
    )
    owner.run.setEnabled(bool(valid and allowed and owner.vm.workspace_id and not owner.submitting))
    return bool(valid and allowed and not owner.submitting)


def page_layout(tabs: QTabWidget, index: int) -> QVBoxLayout:
    page = tabs.widget(index)
    assert page is not None
    layout = page.layout()
    assert isinstance(layout, QVBoxLayout)
    return layout
