"""Explicit RPC/fallback connection controls; password transport never enters history."""

from pathlib import Path

from pydantic import SecretStr, ValidationError
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.presentation import StatusBadge, enhance
from shared.framework import Confirmation, ConnectionStatus, RpcConnect


class ConnectionPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.certificate = ""
        self.status = ConnectionStatus()
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Metasploit connection"))
        help_text = QLabel(
            "Run the Toolkit-MSF setup script first. RPC uses its public TLS certificate.\n"
            "Fallback starts a dedicated console owned by this app."
        )
        help_text.setWordWrap(True)
        layout.addWidget(help_text)
        form = QFormLayout()
        self.host = QLineEdit("127.0.0.1")
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(55553)
        self.user = QLineEdit("msf")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setMaxLength(4096)
        self.remember = QCheckBox("Remember RPC password in the OS keyring")
        self.cert_label = QLabel("No certificate selected")
        self.cert_label.setTextFormat(Qt.TextFormat.PlainText)
        choose = QPushButton("Choose public certificate…")
        choose.clicked.connect(self.choose_certificate)
        for label, widget in (
            ("Host", self.host),
            ("Port", self.port),
            ("Username", self.user),
            ("Password", self.password),
            ("", self.remember),
            ("TLS", choose),
            ("", self.cert_label),
        ):
            form.addRow(label, widget)
        layout.addLayout(form)
        buttons = QHBoxLayout()
        for title, action in (
            ("Connect RPC", self.connect_rpc),
            ("Start owned fallback", self.fallback),
            ("Disconnect", self.disconnect),
            ("Refresh", self.refresh),
        ):
            button = QPushButton(title)
            button.clicked.connect(action)
            buttons.addWidget(button)
        layout.addLayout(buttons)
        self.message = StatusBadge(self.status.message)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        layout.addStretch()
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        enhance(self)

    def choose_certificate(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Public RPC certificate", "", "Certificates (*.crt *.pem);;All files (*)"
        )
        if not path:
            return
        try:
            with Path(path).open("rb") as stream:
                data = stream.read(32769)
            if len(data) > 32768 or b"PRIVATE KEY" in data:
                raise ValueError("Choose the public certificate, never the private key.")
            self.certificate = data.decode("ascii")
            self.cert_label.setText(Path(path).name)
        except (OSError, ValueError):
            self.message.setText("Choose a readable public PEM certificate under 32 KiB.")

    def connect_rpc(self) -> None:
        try:
            data = RpcConnect(
                host=self.host.text(),
                port=self.port.value(),
                username=self.user.text(),
                password=SecretStr(self.password.text()) if self.password.text() else None,
                ca_pem=self.certificate,
                remember_password=self.remember.isChecked(),
            )
        except ValidationError:
            self.message.setText(
                "Check the literal host, username, password and public certificate."
            )
            return
        self.password.clear()
        self.message.setText("Connecting…")
        self.vm.mutate("connection", "POST", "/api/v1/connection/connect", ConnectionStatus, data)

    def fallback(self) -> None:
        self.message.setText("Starting the dedicated console; this can take up to a minute…")
        self.vm.mutate(
            "connection",
            "POST",
            "/api/v1/connection/fallback",
            ConnectionStatus,
            Confirmation(confirmed=True),
        )

    def disconnect(self) -> None:
        confirmed = False
        if self.status.owned:
            confirmed = (
                QMessageBox.question(
                    self,
                    "Stop owned framework?",
                    "This stops the app's owned console and all its sessions and jobs.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            )
            if not confirmed:
                return
        self.vm.mutate(
            "connection",
            "POST",
            "/api/v1/connection/disconnect",
            ConnectionStatus,
            Confirmation(confirmed=confirmed),
        )

    def refresh(self) -> None:
        self.vm.get("connection-status", "/api/v1/connection", ConnectionStatus)

    def update_state(self, key: str, value: object) -> None:
        if key in {"connection", "connection-status"} and isinstance(value, ConnectionStatus):
            self.status = value
            self.message.setText(f"{value.state}: {value.message}")

    def error(self, key: str, message: str) -> None:
        if key.startswith("connection"):
            self.message.setText(message + " Refresh status before trying again.")
