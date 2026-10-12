"""Uploaded volume and protocol analysis."""

from PyQt6.QtWidgets import QDoubleSpinBox, QFormLayout, QSpinBox

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import FilePanel
from frontend.widgets.presentation import enhance
from shared.tools import AnomalyOptions


class Panel(FilePanel):
    tool_id, title = "anomaly-detector", "Network Anomaly Detector"
    description = TOOL_DESCRIPTIONS["anomaly-detector"]

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.interval, self.baseline, self.threshold = QSpinBox(), QSpinBox(), QDoubleSpinBox()
        self.interval.setRange(1, 3600)
        self.interval.setValue(1)
        self.baseline.setRange(2, 120)
        self.baseline.setValue(30)
        self.threshold.setRange(0.1, 20)
        self.threshold.setValue(3)
        form = QFormLayout()
        for label, control in (
            ("Bin seconds", self.interval),
            ("Baseline bins", self.baseline),
            ("Z threshold", self.threshold),
        ):
            form.addRow(label, control)
        self.controls.addLayout(form)
        enhance(self)

    def options(self) -> AnomalyOptions:
        return AnomalyOptions(
            bin_seconds=self.interval.value(),
            baseline_bins=self.baseline.value(),
            threshold=self.threshold.value(),
        )
