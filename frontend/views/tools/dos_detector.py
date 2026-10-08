"""Uploaded log/CSV spike analysis."""

from PyQt6.QtWidgets import QFormLayout, QSpinBox

from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import FilePanel
from shared.tools import DoSOptions


class Panel(FilePanel):
    tool_id, title = "dos-detector", "DoS Pattern Detector"
    description = (
        "Upload UTF-8 access logs or request CSV. Counts strictly above the threshold "
        "in UTC one-second bins are flagged. A spike alone does not establish an attack. "
        "Saved captures require the separate PCAP worker."
    )

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.threshold = QSpinBox()
        self.threshold.setRange(1, 1000000)
        self.threshold.setValue(100)
        form = QFormLayout()
        form.addRow("Requests per IP / second", self.threshold)
        self.controls.addLayout(form)

    def options(self) -> DoSOptions:
        return DoSOptions(threshold=self.threshold.value())
