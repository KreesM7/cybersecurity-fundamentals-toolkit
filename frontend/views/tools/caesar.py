"""Caesar exercise input panel."""

from PyQt6.QtWidgets import QCheckBox, QFormLayout, QPlainTextEdit, QSpinBox

from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from shared.tools import CaesarOptions


class Panel(ToolPanel):
    tool_id, title = "caesar", "Caesar Cipher"
    description = (
        "Shift ASCII letters; preserve case and punctuation. Up to 100,000 characters. "
        "This exercise cipher does not protect sensitive information."
    )

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.source = QPlainTextEdit()
        self.source.setPlaceholderText("Enter text")
        self.controls.addWidget(self.source)
        form = QFormLayout()
        self.shift = QSpinBox()
        self.shift.setRange(1, 25)
        self.shift.setValue(3)
        self.decrypt = QCheckBox("Decrypt")
        form.addRow("Shift", self.shift)
        form.addRow(self.decrypt)
        self.controls.addLayout(form)

    def options(self) -> CaesarOptions:
        return CaesarOptions(
            text=self.source.toPlainText(),
            shift=self.shift.value(),
            decrypt=self.decrypt.isChecked(),
        )
