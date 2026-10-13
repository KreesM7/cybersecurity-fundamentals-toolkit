"""Shared field help, accessible page chrome, guides and labeled status badges."""

from collections.abc import Callable

from PyQt6.QtCore import QEvent, QObject, Qt
from PyQt6.QtGui import QFontDatabase, QPainter, QPaintEvent
from PyQt6.QtWidgets import (
    QAbstractButton,
    QAbstractItemView,
    QAbstractSpinBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.help_text import COPY, GUIDE_HEADINGS, GUIDES, FieldHelp, field_help
from frontend.icons import line_icon
from frontend.theme import SIZE, SPACE

INPUTS = (
    QLineEdit,
    QPlainTextEdit,
    QComboBox,
    QAbstractSpinBox,
    QAbstractItemView,
    QAbstractButton,
)


def explain(widget: QWidget, info: FieldHelp) -> None:
    widget.setToolTip(info.tooltip())
    widget.setAccessibleName(info.title)
    widget.setAccessibleDescription(info.what)
    widget.setProperty("helpWhat", info.what)
    widget.setProperty("helpExample", info.example)
    widget.setProperty("helpWrong", info.wrong)
    if isinstance(widget, (QLineEdit, QPlainTextEdit)):
        widget.setPlaceholderText(info.example)
    if isinstance(widget, QComboBox) and widget.isEditable() and widget.lineEdit():
        line_edit = widget.lineEdit()
        if line_edit:
            explain(line_edit, info)
    if isinstance(widget, QAbstractSpinBox):
        line = widget.findChild(QLineEdit)
        if line:
            explain(line, info)


def popover(field: QWidget) -> None:
    dialog = QDialog(field)
    dialog.setWindowTitle(field.accessibleName())
    dialog.resize(SIZE["dialog_w"], SIZE["dialog_h"])
    layout = QVBoxLayout(dialog)
    for title, value in (
        ("What it is / what to enter", field.property("helpWhat") or field.toolTip()),
        ("Example", field.property("helpExample")),
        ("If the value is wrong", field.property("helpWrong")),
    ):
        label = QLabel(f'{title}\n{value or ""}')
        label.setTextFormat(Qt.TextFormat.PlainText)
        label.setWordWrap(True)
        layout.addWidget(label)
    close = QPushButton("Close")
    close.setAccessibleName("Close field help")
    close.clicked.connect(dialog.accept)
    layout.addWidget(close)
    dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    dialog.show()
    close.setFocus()


class HelpButton(QPushButton):
    def changeEvent(self, event: QEvent | None) -> None:  # noqa: N802
        if event and event.type() == QEvent.Type.PaletteChange:
            self.setIcon(line_icon("help"))
        super().changeEvent(event)


def help_button(field: QWidget) -> QPushButton:
    button = HelpButton()
    button.setIcon(line_icon("help"))
    button.setFixedWidth(SIZE["control"])
    button.setAccessibleName("Help: " + field.accessibleName())
    button.setToolTip(field.toolTip())
    button.clicked.connect(lambda: popover(field))
    return button


def polish_field(widget: QWidget, identifier: str = "") -> None:
    if not isinstance(widget, INPUTS + (QTabBar,)):
        return
    key = identifier or str(widget.property("fieldId") or widget.objectName())
    if not widget.toolTip():
        label = widget.text() if isinstance(widget, QAbstractButton) else key
        if isinstance(widget, QPlainTextEdit) and widget.isReadOnly():
            explain(widget, FieldHelp("Output", COPY["output"], "Completed analysis results"))
        else:
            explain(widget, field_help(key or type(widget).__name__, label))
    if not widget.accessibleName():
        widget.setAccessibleName(key or type(widget).__name__)
    if isinstance(widget, QAbstractButton):
        title = widget.text().casefold()
        widget.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        if any(word in title for word in ("delete", "stop", "cancel", "kill")):
            widget.setProperty("role", "danger")
        elif title.startswith(("run", "generate", "save", "create", "connect", "unlock")):
            widget.setProperty("role", "primary")
    if isinstance(widget, QPlainTextEdit) or (
        isinstance(widget, QLineEdit)
        and any(
            word in key.lower() for word in ("address", "host", "token", "hash", "command", "url")
        )
    ):
        widget.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
    if isinstance(widget, QPlainTextEdit):
        widget.setTabChangesFocus(True)
    if isinstance(widget, QAbstractItemView):
        widget.setAlternatingRowColors(True)


def enhance(panel: QWidget) -> None:
    prefix = str(getattr(panel, "tool_id", type(panel).__name__))
    for name, value in vars(panel).items():
        if isinstance(value, QWidget) and isinstance(value, INPUTS):
            value.setProperty("fieldId", prefix + "." + name)
            if not value.property("helpWhat"):
                info = (
                    FieldHelp("Output", COPY["output"], "Results appear here after an action")
                    if isinstance(value, QPlainTextEdit) and value.isReadOnly()
                    else field_help(prefix + "." + name, name.replace("_", " "))
                )
                explain(value, info)
    for layout in panel.findChildren(QLayout):
        layout.setSpacing(SPACE["sm"])
        layout.setContentsMargins(SPACE["sm"], SPACE["sm"], SPACE["sm"], SPACE["sm"])
    for widget in panel.findChildren(QWidget):
        polish_field(widget)
        if (
            isinstance(widget, QAbstractItemView)
            and not isinstance(widget, QHeaderView)
            and not widget.property("emptyHelp")
        ):
            widget.setProperty("emptyHelp", True)
            EmptyTableHelp(widget)
    for form in panel.findChildren(QFormLayout):
        for row_index in range(form.rowCount()):
            item = form.itemAt(row_index, QFormLayout.ItemRole.FieldRole)
            field = item.widget() if item else None
            if not field or not isinstance(field, INPUTS) or field.property("helpWrapped"):
                continue
            field.setProperty("helpWrapped", True)
            wrapper = QWidget()
            row = QHBoxLayout(wrapper)
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(SPACE["xs"])
            form.replaceWidget(field, wrapper)
            row.addWidget(field, 1)
            row.addWidget(help_button(field))
    labels = panel.findChildren(QLabel)
    if labels and not panel.findChildren(QLabel, "pageTitle"):
        labels[0].setObjectName("pageTitle")


class FocusHelp(QObject):
    def __init__(self, hint: QLabel, parent: QObject) -> None:
        super().__init__(parent)
        self.hint = hint

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802
        if isinstance(watched, QWidget) and event:
            if event.type() in (QEvent.Type.Show, QEvent.Type.FocusIn):
                polish_field(watched)
            if event.type() == QEvent.Type.FocusIn and watched.toolTip():
                self.hint.setText(watched.toolTip())
        return False


class EmptyTableHelp(QLabel):
    def __init__(self, view: QAbstractItemView) -> None:
        super().__init__(COPY["empty_table"], view.viewport())
        self.view = view
        self.setWordWrap(True)
        self.setProperty("role", "muted")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        viewport = view.viewport()
        if viewport:
            viewport.installEventFilter(self)
        model = view.model()
        if model:
            model.rowsInserted.connect(self.refresh)
            model.rowsRemoved.connect(self.refresh)
            model.modelReset.connect(self.refresh)
        self.refresh()

    def refresh(self, *_: object) -> None:
        model = self.view.model()
        viewport = self.view.viewport()
        if viewport:
            self.setGeometry(
                viewport.rect().adjusted(SPACE["sm"], SPACE["sm"], -SPACE["sm"], -SPACE["sm"])
            )
        self.setVisible(bool(model and model.rowCount() == 0))

    def eventFilter(self, watched: QObject | None, event: QEvent | None) -> bool:  # noqa: N802
        if event and event.type() in (QEvent.Type.Resize, QEvent.Type.Show):
            self.refresh()
        return False


class LoadingSkeleton(QProgressBar):
    """One compact shared loading placeholder; only active while awaiting work."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setRange(0, 0)
        self.setTextVisible(False)
        self.setFixedHeight(SPACE["sm"])
        self.setAccessibleName("Working; awaiting results")
        self.hide()


class StatusBadge(QLabel):
    def __init__(self, text: str = "Ready", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setWordWrap(True)
        self.setMargin(SPACE["xs"])
        self.setContentsMargins(SIZE["icon"] + SPACE["sm"], 0, 0, 0)
        self.setText(text)

    def paintEvent(self, event: QPaintEvent | None) -> None:  # noqa: N802
        super().paintEvent(event)
        painter = QPainter(self)
        state = str(self.property("state"))
        icon = {"done": "ready", "cancelled": "failed", "unknown": "help", "idle": "help"}.get(
            state, state
        )
        line_icon(icon).paint(
            painter, SPACE["xs"], (self.height() - SIZE["icon"]) // 2, SIZE["icon"], SIZE["icon"]
        )
        painter.end()

    def set_status(self, text: str, state: str) -> None:
        """Use the existing badge appearance with an explicit readiness state."""
        if state not in {"ready", "running", "done", "failed", "cancelled", "unknown", "idle"}:
            raise ValueError("Unknown badge state")
        self.setText(text)
        self.setProperty("state", state)
        QLabel.setText(self, text)
        self.setAccessibleName(state.title() + ": " + text)
        style = self.style()
        if style:
            style.unpolish(self)
            style.polish(self)

    def setText(self, text: str | None) -> None:  # noqa: N802
        value = text or "Ready"
        self.raw_text = value
        state = (
            "failed"
            if any(w in value.lower() for w in ("error", "failed", "invalid"))
            else (
                "running"
                if any(
                    w in value.lower() for w in ("loading", "running", "submitting", "searching")
                )
                else (
                    "done"
                    if any(
                        w in value.lower()
                        for w in ("done", "succeeded", "saved", "completed", "verified")
                    )
                    else "ready"
                )
            )
        )
        if value.casefold() == "cancelled":
            state = "cancelled"
        self.setProperty("state", state)
        self.setAccessibleName(state.title() + ": " + value)
        super().setText(
            value if value.casefold().startswith(state) else state.title() + " · " + value
        )
        style = self.style()
        if style:
            style.unpolish(self)
            style.polish(self)


def guide_tabs(panel: QWidget, key: str, example: Callable[[], None]) -> QTabWidget:
    previous = panel.layout()
    if previous and previous.count():
        first = previous.itemAt(0)
        run_heading = first.widget() if first else None
        if isinstance(run_heading, QLabel):
            run_heading.setObjectName("pageTitle")
    run = QWidget()
    if previous:
        run.setLayout(previous)
    root = QVBoxLayout(panel)
    root.setContentsMargins(0, 0, 0, 0)
    tabs = QTabWidget()
    tabs.setAccessibleName("Run and guide")
    tabs.addTab(run, "Run")
    guide = QWidget()
    content = QVBoxLayout(guide)
    for heading, section in zip(GUIDE_HEADINGS, GUIDES[key], strict=True):
        title = QLabel(heading)
        title.setProperty("role", "section")
        content.addWidget(title)
        body = (
            "\n".join(f"{i}. {step}" for i, step in enumerate(section, 1))
            if isinstance(section, tuple)
            else section
        )
        label = QLabel(str(body))
        label.setWordWrap(True)
        label.setTextFormat(Qt.TextFormat.PlainText)
        content.addWidget(label)
    content.addStretch()
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setWidget(guide)
    tabs.addTab(scroll, "Guide")
    root.addWidget(tabs)
    button = QPushButton("Try example")
    button.setToolTip(COPY["example"])
    button.setAccessibleName("Fill safe example")
    button.clicked.connect(example)
    if isinstance(previous, QVBoxLayout):
        previous.insertWidget(1, button)
    enhance(panel)
    return tabs


def input_dialog(
    parent: QWidget, title: str, label: str, key: str, *, secret: bool = False
) -> tuple[str, bool]:
    from PyQt6.QtWidgets import QDialogButtonBox, QInputDialog

    dialog = QInputDialog(parent)
    dialog.setWindowTitle(title)
    dialog.setLabelText(label)
    dialog.setTextEchoMode(QLineEdit.EchoMode.Password if secret else QLineEdit.EchoMode.Normal)
    dialog.setTextValue("")
    field = dialog.findChild(QLineEdit)
    if field:
        explain(field, field_help(key))
        layout = dialog.layout()
        if layout:
            layout.addWidget(help_button(field))
    for buttons in dialog.findChildren(QDialogButtonBox):
        for button in buttons.buttons():
            polish_field(button)
    accepted = dialog.exec() == QDialog.DialogCode.Accepted
    return dialog.textValue(), accepted
