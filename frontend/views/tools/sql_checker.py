"""Captured discovery and generation-safe editable form presentation."""

from uuid import UUID

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
)

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from frontend.widgets.presentation import enhance
from shared.tools import SQLField, SQLForm, SQLOptions, ToolOptions


class Panel(ToolPanel):
    tool_id, title = "sql-checker", "SQL Injection Checker"
    description = TOOL_DESCRIPTIONS["sql-checker"]

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.target_generation = 0
        self.discovery_id: UUID | None = None
        self.source_url = ""
        self.discovered_forms: list[SQLForm] = []
        self.url = QLineEdit("http://127.0.0.1:8000/")
        self.forms = QComboBox()
        self.fields = QTableWidget(0, 2)
        self.fields.setHorizontalHeaderLabels(["Field", "Value (editable)"])
        header = self.fields.horizontalHeader()
        if header is not None:
            header.setStretchLastSection(True)
        self.post = QCheckBox("Enable POST testing for the selected form")
        form = QFormLayout()
        form.addRow("Target URL", self.url)
        form.addRow("Selected form", self.forms)
        self.controls.addLayout(form)
        self.controls.addWidget(self.fields)
        self.controls.addWidget(self.post)
        self.run_button.setText("Load forms")
        self.test_button = QPushButton("Test selected form")
        self.test_button.setEnabled(False)
        self.test_button.clicked.connect(self.test_selected)
        self.actions_layout.insertWidget(1, self.test_button)
        self.url.textChanged.connect(self._target_changed)
        self.forms.currentIndexChanged.connect(self._select)
        enhance(self)

    def _target_changed(self, value: str) -> None:
        self.target_generation += 1
        self.discovery_id = None
        self.discovered_forms.clear()
        self.forms.clear()
        self.fields.setRowCount(0)
        self.post.setChecked(False)
        self.test_button.setEnabled(False)
        self.vm.clear(self.tool_id)
        self.output.clear()

    def _select(self, index: int) -> None:
        self.post.setChecked(False)
        form = self.discovered_forms[index] if 0 <= index < len(self.discovered_forms) else None
        self.fields.setRowCount(len(form.fields) if form else 0)
        if form is not None:
            for row, field in enumerate(form.fields):
                label = QTableWidgetItem(field.name)
                label.setFlags(label.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.fields.setItem(row, 0, label)
                self.fields.setItem(row, 1, QTableWidgetItem(field.value))
        self.test_button.setEnabled(form is not None)

    def options(self) -> SQLOptions:
        return SQLOptions(url=self.url.text(), generation=self.target_generation)

    def prepare_terminal_options(self, options: ToolOptions) -> SQLOptions:
        if not isinstance(options, SQLOptions):
            raise ValueError("SQL options required.")
        if options.operation == "discover":
            self.url.setText(options.url)
            return options.model_copy(update={"generation": self.target_generation})
        return options

    def show_result(self, result: object) -> None:
        if isinstance(result, dict) and "discovery_id" in result:
            if result.get("generation") != self.target_generation:
                self.status.setText("Target changed during discovery. Load forms again.")
                return
            self.discovery_id = UUID(str(result["discovery_id"]))
            self.source_url = str(result["source_url"])
            self.discovered_forms = [
                SQLForm.model_validate(form) for form in result.get("forms", [])
            ]
            self.forms.clear()
            for form in self.discovered_forms:
                self.forms.addItem(f"{form.method} {form.action}")
            self._select(self.forms.currentIndex())
        super().show_result(result)

    def test_selected(self) -> None:
        if self.discovery_id is None or not self.discovered_forms:
            self.status.setText("Load forms for the current URL first.")
            return
        index = self.forms.currentIndex()
        form = self.discovered_forms[index]
        try:
            fields = []
            for row, field in enumerate(form.fields):
                item = self.fields.item(row, 1)
                fields.append(SQLField(name=field.name, value=item.text() if item else ""))
            options = SQLOptions(
                operation="test",
                url=self.source_url,
                allow_post=self.post.isChecked(),
                generation=self.target_generation,
                discovery_id=self.discovery_id,
                form_index=index,
                fields=fields,
            )
            self.vm.submit(options)
        except ValueError:
            self.status.setText(
                "Check required fields and input limits (65,536 characters per field value)."
            )
            return
        self.output.clear()
        self.status.setText("Testing selected form…")

    def clear(self) -> None:
        self._target_changed(self.url.text())
        super().clear()
