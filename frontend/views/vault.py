"""Explicit credential acceptance, reauthentication and automatic removal of revealed text."""

from pydantic import SecretStr, ValidationError
from PyQt6.QtCore import QIODevice, QSaveFile, Qt, QTimer
from PyQt6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from shared.activity import ActionResult
from shared.vault import (
    CredentialInput,
    CredentialList,
    CredentialReveal,
    CredentialSaved,
    CredentialSummary,
    VaultChange,
    VaultExport,
    VaultPassword,
    VaultStatus,
    VaultToken,
    VaultUnlock,
)


class VaultPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self._export_path = ""
        self._unlocked = False
        root = QVBoxLayout(self)
        self.status = QLabel("Vault locked. Keys remain in memory only while unlocked.")
        self.status.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.status)
        row = QHBoxLayout()
        for label, action in (
            ("Initialize", lambda: self.unlock(True)),
            ("Unlock", lambda: self.unlock(False)),
            ("Lock", self.lock),
            ("Change password", self.change),
            ("Export plaintext…", self.export),
        ):
            button = QPushButton(label)
            button.clicked.connect(action)
            row.addWidget(button)
        root.addLayout(row)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["State", "Service", "Username"])
        root.addWidget(self.tree, 1)
        form = QFormLayout()
        self.service, self.username, self.secret = QLineEdit(), QLineEdit(), QLineEdit()
        self.secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.secret.setMaxLength(8192)
        for label, widget in (
            ("Service", self.service),
            ("Username", self.username),
            ("Secret", self.secret),
        ):
            form.addRow(label, widget)
        root.addLayout(form)
        row = QHBoxLayout()
        for label, action in (
            ("Add temporary candidate", self.candidate),
            ("Accept candidate", self.accept),
            ("Delete / discard", self.delete),
            ("Reveal for 30 seconds", self.reveal),
            ("Refresh", self.refresh),
        ):
            button = QPushButton(label)
            button.clicked.connect(action)
            row.addWidget(button)
        root.addLayout(row)
        self.revealed = QLineEdit()
        self.revealed.setReadOnly(True)
        root.addWidget(self.revealed)
        self.hide_timer = QTimer(self)
        self.hide_timer.setSingleShot(True)
        self.hide_timer.timeout.connect(self.revealed.clear)
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(5000)
        self.status_timer.timeout.connect(self.check_status)
        self.status_timer.start()
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)

    def password(self, title: str = "Vault password") -> SecretStr | None:
        text, accepted = QInputDialog.getText(
            self, title, "Master passphrase", QLineEdit.EchoMode.Password
        )
        return SecretStr(text) if accepted and text else None

    def unlock(self, initialize: bool) -> None:
        password = self.password("Initialize vault" if initialize else "Unlock vault")
        if password:
            self.vm.vault_request(
                "vault-unlock",
                "POST",
                "unlock",
                VaultToken,
                VaultUnlock(password=password, initialize=initialize),
            )

    def clear(self) -> None:
        self._unlocked = False
        self.vm.clear_vault_state()
        self.tree.clear()
        self.secret.clear()
        self.revealed.clear()
        self._export_path = ""
        self.hide_timer.stop()

    def lock(self) -> None:
        self.clear()
        self.vm.vault_request("vault-lock", "POST", "lock", ActionResult)

    def check_status(self) -> None:
        if self.vm.workspace_id:
            self.vm.vault_request("vault-status", "GET", "status", VaultStatus)

    def refresh(self) -> None:
        if self.vm.vault_token:
            self.vm.vault_request("vault-list", "GET", "credentials", CredentialList)

    def candidate(self) -> None:
        try:
            data = CredentialInput(
                service=self.service.text(),
                username=self.username.text(),
                secret=SecretStr(self.secret.text()),
            )
        except ValidationError:
            self.status.setText("Enter a service and secret within the field limits.")
            return
        self.secret.clear()
        self.vm.vault_request("vault-candidate", "POST", "candidates", CredentialSaved, data)

    def selected(self) -> tuple[str, CredentialSummary] | None:
        item = self.tree.currentItem()
        value = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        return value if isinstance(value, tuple) else None

    def accept(self) -> None:
        row = self.selected()
        if row and row[0] == "Candidate":
            self.vm.vault_request(
                "vault-accept", "POST", f"candidates/{row[1].id}/accept", CredentialSaved
            )

    def delete(self) -> None:
        row = self.selected()
        if (
            row
            and QMessageBox.question(
                self,
                "Remove credential?",
                "Delete this saved credential or discard this candidate?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        ):
            kind = "candidates" if row[0] == "Candidate" else "credentials"
            self.vm.vault_request("vault-delete", "DELETE", f"{kind}/{row[1].id}", ActionResult)

    def reveal(self) -> None:
        row = self.selected()
        if row and row[0] == "Saved":
            password = self.password("Reauthenticate to reveal")
            if password:
                self.vm.vault_request(
                    "vault-reveal",
                    "POST",
                    f"credentials/{row[1].id}/reveal",
                    CredentialReveal,
                    VaultPassword(password=password),
                )

    def change(self) -> None:
        previous = self.password("Current master passphrase")
        if previous:
            replacement = self.password("New master passphrase (12+ characters)")
            if replacement:
                try:
                    data = VaultChange(password=previous, new_password=replacement)
                except ValidationError:
                    self.status.setText("Use at least 12 characters for the new passphrase.")
                    return
                self.vm.vault_request("vault-change", "POST", "change-password", ActionResult, data)

    def export(self) -> None:
        if (
            QMessageBox.question(
                self,
                "Export plaintext credentials?",
                "This explicitly saves unencrypted credentials to a file you choose. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export plaintext vault", "credentials.json", "JSON (*.json)"
        )
        if path:
            password = self.password("Reauthenticate to export")
            if password:
                self._export_path = path
                self.vm.vault_request(
                    "vault-export", "POST", "export", VaultExport, VaultPassword(password=password)
                )

    def update_state(self, key: str, value: object) -> None:
        if key in {"workspace", "vault-locked", "vault-lock", "vault-change"}:
            self.clear()
            self.status.setText("Vault locked. Unlock the selected workspace vault.")
        elif key == "vault-unlock" and isinstance(value, VaultToken):
            self.vm.vault_token = SecretStr(value.token)
            self._unlocked = True
            self.status.setText(
                "Unlocked · 15-minute session · locks after 5 minutes of inactivity"
            )
            self.refresh()
        elif key == "vault-status" and isinstance(value, VaultStatus):
            if not value.unlocked and self._unlocked:
                self.clear()
                self.status.setText("Vault locked automatically.")
        elif key == "vault-list" and isinstance(value, CredentialList):
            self.tree.clear()
            for label, rows in (("Candidate", value.candidates), ("Saved", value.credentials)):
                for row in rows:
                    item = QTreeWidgetItem([label, row.service, row.username])
                    item.setData(0, Qt.ItemDataRole.UserRole, (label, row))
                    self.tree.addTopLevelItem(item)
        elif key == "vault-reveal" and isinstance(value, CredentialReveal):
            self.revealed.setText(value.secret)
            self.hide_timer.start(30000)
        elif key == "vault-export" and isinstance(value, VaultExport) and self._export_path:
            output = QSaveFile(self._export_path)
            self._export_path = ""
            encoded = value.content.encode("utf-8")
            if (
                output.open(QIODevice.OpenModeFlag.WriteOnly)
                and output.write(encoded) == len(encoded)
                and output.commit()
            ):
                self.status.setText("Plaintext export saved to your chosen file.")
            else:
                output.cancelWriting()
                self.status.setText("Export could not be saved. Check the destination.")
        elif key in {"vault-candidate", "vault-accept", "vault-delete"}:
            self.refresh()

    def error(self, key: str, message: str) -> None:
        if key.startswith("vault"):
            self.status.setText(message)
            self.revealed.clear()
            self._export_path = ""
