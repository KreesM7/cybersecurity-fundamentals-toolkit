"""Masked password input with session-only results."""

from pydantic import SecretStr
from PyQt6.QtWidgets import QCheckBox, QLineEdit

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from frontend.widgets.presentation import enhance
from shared.tools import PasswordOptions


class Panel(ToolPanel):
    tool_id, title = "password-strength", "Password Strength"
    description = TOOL_DESCRIPTIONS["password-strength"]

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.show_password = QCheckBox("Show password")
        self.show_password.toggled.connect(
            lambda visible: self.password.setEchoMode(
                QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
            )
        )
        self.controls.addWidget(self.password)
        self.controls.addWidget(self.show_password)
        enhance(self)

    def options(self) -> PasswordOptions:
        return PasswordOptions(password=SecretStr(self.password.text()))

    def clear(self) -> None:
        super().clear()
        self.password.clear()
        self.show_password.setChecked(False)
