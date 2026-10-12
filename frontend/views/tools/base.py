"""Compact REST-driven tool panels; views contain presentation and user input only."""

import json

from PyQt6.QtGui import QFontDatabase
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.widgets.examples import fill_example
from frontend.widgets.presentation import LoadingSkeleton, StatusBadge, enhance, guide_tabs
from shared.tools import ToolJob, ToolOptions


class ToolPanel(QWidget):
    tool_id = ""
    title = ""
    description = ""

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__()
        self.vm = view_model
        self.content = QVBoxLayout(self)
        heading = QLabel(self.title)
        heading.setObjectName("pageTitle")
        self.content.addWidget(heading)
        help_text = QLabel(self.description)
        help_text.setWordWrap(True)
        self.content.addWidget(help_text)
        self.controls = QVBoxLayout()
        self.content.addLayout(self.controls)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.content.addWidget(self.output, 1)
        self.actions_layout = QHBoxLayout()
        self.run_button = QPushButton("Run")
        self.cancel_button = QPushButton("Cancel")
        self.clear_button = QPushButton("Clear")
        for button in (self.run_button, self.cancel_button, self.clear_button):
            self.actions_layout.addWidget(button)
        self.actions_layout.addStretch()
        self.content.addLayout(self.actions_layout)
        self.status = StatusBadge("Ready. Results stay in this session.")
        self.status.setWordWrap(True)
        self.content.addWidget(self.status)
        self.loading = LoadingSkeleton()
        self.content.addWidget(self.loading)
        self.run_button.clicked.connect(self.run)
        self.cancel_button.clicked.connect(lambda: self.vm.cancel(self.tool_id))
        self.clear_button.clicked.connect(self.clear)
        self.guide_tabs = guide_tabs(self, self.tool_id, lambda: fill_example(self, self.tool_id))
        self.vm.job_changed.connect(self._job)
        self.vm.tool_error.connect(self._error)
        enhance(self)

    def options(self) -> ToolOptions:
        raise NotImplementedError

    def run(self) -> None:
        try:
            self.vm.submit(self.options())
            self.loading.show()
            self.output.clear()
            self.status.setText("Submitting…")
        except ValueError:
            self.status.setText("Check the input limits and required fields.")

    def clear(self) -> None:
        self.loading.hide()
        self.vm.clear(self.tool_id)
        self.output.clear()
        self.status.setText("Cleared.")

    def _error(self, tool_id: str, message: str) -> None:
        if tool_id == self.tool_id:
            self.loading.hide()
            self.status.setText(message)

    def _job(self, tool_id: str, value: object) -> None:
        if tool_id == self.tool_id and isinstance(value, ToolJob):
            self.loading.setVisible(value.status in {"queued", "running", "cancelling"})
            self.status.setText(value.error or value.progress or value.status.capitalize())
            if value.status == "succeeded":
                self.show_result(value.result)

    def show_result(self, result: object) -> None:
        # Infinity is a presentation value; transport uses null plus explicit score_kind.
        def display(value: object) -> object:
            if isinstance(value, dict):
                result = {key: display(item) for key, item in value.items()}
                if value.get("score_kind") in ("positive_infinity", "negative_infinity"):
                    result["zscore"] = "∞" if value["score_kind"] == "positive_infinity" else "−∞"
                return result
            if isinstance(value, list):
                return [display(item) for item in value]
            return value

        self.output.setPlainText(json.dumps(display(result), indent=2, ensure_ascii=False))
        if isinstance(result, dict) and isinstance(result.get("error"), dict):
            self.status.setText(str(result["error"].get("message", "Check input and readiness.")))


class FilePanel(ToolPanel):
    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        row = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        browse = QPushButton("Choose file…")
        browse.clicked.connect(self.choose_file)
        row.addWidget(self.file_path, 1)
        row.addWidget(browse)
        self.controls.addLayout(row)
        enhance(self)

    def choose_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Choose input file")
        if filename:
            self.file_path.setText(filename)

    def run(self) -> None:
        if not self.file_path.text():
            self.status.setText("Choose a readable input file.")
            return
        self.vm.submit(self.options(), self.file_path.text())
        self.loading.show()
        self.output.clear()
        self.status.setText("Uploading and analyzing…")
