"""System-routing or local-interface scanner inputs."""

from PyQt6.QtWidgets import QComboBox, QFormLayout, QLineEdit, QPushButton

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from frontend.widgets.presentation import enhance
from shared.tools import InterfaceView, ScannerOptions


class Panel(ToolPanel):
    tool_id, title = "network-scanner", "Network Scanner"
    description = TOOL_DESCRIPTIONS["network-scanner"]

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.target = QLineEdit()
        self.interfaces = QComboBox()
        self.interfaces.addItem("Entered target (system routing)", None)
        refresh = QPushButton("Refresh interfaces")
        refresh.clicked.connect(self.vm.refresh_interfaces)
        form = QFormLayout()
        form.addRow("Target routing", self.interfaces)
        form.addRow("IPv4 address / CIDR", self.target)
        form.addRow(refresh)
        self.controls.addLayout(form)
        self.vm.interfaces_changed.connect(self._interfaces)
        enhance(self)

    def _interfaces(self, values: object) -> None:
        self.interfaces.clear()
        self.interfaces.addItem("Entered target (system routing)", None)
        if isinstance(values, list):
            for value in values:
                if isinstance(value, InterfaceView):
                    self.interfaces.addItem(f"{value.name}: {value.ip}", value)

    def options(self) -> ScannerOptions:
        interface = self.interfaces.currentData()
        return ScannerOptions(
            target=self.target.text(),
            interface=interface if isinstance(interface, InterfaceView) else None,
        )
