"""Uploaded log/CSV spike analysis."""

from PyQt6.QtWidgets import QFormLayout, QSpinBox

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import FilePanel
from frontend.widgets.presentation import enhance
from shared.tools import DoSOptions


class Panel(FilePanel):
    tool_id, title = "dos-detector", "DoS Pattern Detector"
    description = TOOL_DESCRIPTIONS["dos-detector"]

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.threshold = QSpinBox()
        self.threshold.setRange(1, 1000000)
        self.threshold.setValue(100)
        form = QFormLayout()
        form.addRow("Requests per IP / second", self.threshold)
        self.controls.addLayout(form)
        enhance(self)

    def options(self) -> DoSOptions:
        return DoSOptions(threshold=self.threshold.value())
