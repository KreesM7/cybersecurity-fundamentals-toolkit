"""Caesar exercise input panel."""

from PyQt6.QtWidgets import QCheckBox, QFormLayout, QPlainTextEdit, QSpinBox

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from frontend.widgets.presentation import enhance
from shared.tools import CaesarOptions


class Panel(ToolPanel):
    tool_id, title = "caesar", "Caesar Cipher"
    description = TOOL_DESCRIPTIONS["caesar"]

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.source = QPlainTextEdit()
        self.controls.addWidget(self.source)
        form = QFormLayout()
        self.shift = QSpinBox()
        self.shift.setRange(1, 25)
        self.shift.setValue(3)
        self.decrypt = QCheckBox("Decrypt")
        form.addRow("Shift", self.shift)
        form.addRow(self.decrypt)
        self.controls.addLayout(form)
        enhance(self)

    def options(self) -> CaesarOptions:
        return CaesarOptions(
            text=self.source.toPlainText(),
            shift=self.shift.value(),
            decrypt=self.decrypt.isChecked(),
        )
