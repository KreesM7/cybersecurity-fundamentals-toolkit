"""Uploaded volume and protocol analysis."""

from PyQt6.QtWidgets import QDoubleSpinBox, QFormLayout, QSpinBox

from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import FilePanel
from shared.tools import AnomalyOptions


class Panel(FilePanel):
    tool_id, title = "anomaly-detector", "Network Anomaly Detector"
    description = (
        "Upload UTF-8 logs or CSV with timestamp, source_ip, bytes and protocol. "
        "By default one-second bins compare against the preceding 30 bins; "
        "absolute z-scores above 3 are flagged. At least 31 bins are needed by default. "
        "Saved captures require the separate PCAP worker."
    )

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

    def options(self) -> AnomalyOptions:
        return AnomalyOptions(
            bin_seconds=self.interval.value(),
            baseline_bins=self.baseline.value(),
            threshold=self.threshold.value(),
        )
