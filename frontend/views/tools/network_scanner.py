"""Authorized system-routing or local-interface scanner inputs."""

from PyQt6.QtWidgets import QCheckBox, QComboBox, QFormLayout, QLineEdit, QPushButton

from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from shared.tools import InterfaceView, ScannerOptions


class Panel(ToolPanel):
    tool_id, title = "network-scanner", "Network Scanner"
    description = (
        "TCP connect scans of authorized IPv4 addresses or CIDRs (up to 256 whole addresses). "
        "Selected interfaces require an RFC1918 contained subnet; entered targets use "
        "system routing. Filtered ports leave host presence inconclusive."
    )

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.target = QLineEdit()
        self.target.setPlaceholderText("Authorized IPv4 address or CIDR")
        self.interfaces = QComboBox()
        self.interfaces.addItem("Entered target (system routing)", None)
        refresh = QPushButton("Refresh interfaces")
        refresh.clicked.connect(self.vm.refresh_interfaces)
        self.owned = QCheckBox("I own this target or have permission to scan it")
        self.target.textChanged.connect(lambda _: self.owned.setChecked(False))
        self.interfaces.currentIndexChanged.connect(lambda _: self.owned.setChecked(False))
        form = QFormLayout()
        form.addRow("Target routing", self.interfaces)
        form.addRow("IPv4 address / CIDR", self.target)
        form.addRow(refresh)
        self.controls.addLayout(form)
        self.controls.addWidget(self.owned)
        self.vm.interfaces_changed.connect(self._interfaces)

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
            authorized=self.owned.isChecked(),
            interface=interface if isinstance(interface, InterfaceView) else None,
        )
