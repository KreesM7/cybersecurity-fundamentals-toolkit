"""Masked password input with session-only results."""

from pydantic import SecretStr
from PyQt6.QtWidgets import QCheckBox, QLineEdit

from frontend.viewmodels.tools_vm import ToolsViewModel
from frontend.views.tools.base import ToolPanel
from shared.tools import PasswordOptions


class Panel(ToolPanel):
    tool_id, title = "password-strength", "Password Strength"
    description = (
        "Local estimator (maximum 72 characters, never truncated). "
        "Strength bits are log2(guesses). Crack times at 10/s, 10,000/s and 10 billion/s "
        "are illustrative. Passwords are sent only to your authenticated local backend "
        "and never saved or logged."
    )

    def __init__(self, view_model: ToolsViewModel) -> None:
        super().__init__(view_model)
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Enter a practice password")
        self.show_password = QCheckBox("Show password")
        self.show_password.toggled.connect(
            lambda visible: self.password.setEchoMode(
                QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
            )
        )
        self.controls.addWidget(self.password)
        self.controls.addWidget(self.show_password)

    def options(self) -> PasswordOptions:
        return PasswordOptions(password=SecretStr(self.password.text()))

    def clear(self) -> None:
        super().clear()
        self.password.clear()
        self.show_password.setChecked(False)
