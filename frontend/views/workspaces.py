"""Workspace, target and artifact forms, backed only by typed API actions."""

import json
from uuid import UUID

from pydantic import RootModel, ValidationError
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from shared.payloads import ArtifactView
from shared.tools import EmptyResponse
from shared.workspaces import (
    TargetBulk,
    TargetCreate,
    TargetStatus,
    TargetUpdate,
    TargetView,
    WorkspaceCreate,
    WorkspaceNotes,
    WorkspaceView,
)


class WorkspacePanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Workspaces"))
        self.workspaces = QComboBox()
        root.addWidget(self.workspaces)
        actions = QHBoxLayout()
        for label, method in (
            ("Create", self.create_workspace),
            ("Switch", self.activate),
            ("Delete inactive", self.delete),
            ("Refresh", vm.refresh_workspaces),
        ):
            button = QPushButton(label)
            button.clicked.connect(method)
            actions.addWidget(button)
        root.addLayout(actions)
        root.addWidget(QLabel("Notes for the active workspace"))
        self.notes = QPlainTextEdit()
        root.addWidget(self.notes, 1)
        self.save = QPushButton("Save notes (Ctrl+S)")
        self.save.clicked.connect(self.save_notes)
        root.addWidget(self.save)
        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.message)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)

    def create_workspace(self) -> None:
        name, accepted = QInputDialog.getText(self, "Create workspace", "Name")
        if accepted and name.strip():
            try:
                data = WorkspaceCreate(name=name)
            except ValidationError:
                self.message.setText("Use a workspace name between 1 and 100 characters.")
                return
            self.vm.mutate("workspace-create", "POST", "/api/v1/workspaces/", WorkspaceView, data)

    def activate(self) -> None:
        identifier = self.workspaces.currentData()
        if identifier:
            self.vm.mutate(
                "workspace-activate",
                "POST",
                f"/api/v1/workspaces/{identifier}/activate",
                WorkspaceView,
            )

    def delete(self) -> None:
        identifier = self.workspaces.currentData()
        if identifier and identifier != self.vm.workspace_id:
            if (
                QMessageBox.question(
                    self,
                    "Delete workspace?",
                    "Permanently delete this inactive workspace and its saved data? "
                    "Remote session/job associations will be lost; "
                    "external activity keeps running.",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self.vm.mutate(
                    "workspace-delete", "DELETE", f"/api/v1/workspaces/{identifier}", EmptyResponse
                )

    def save_notes(self) -> None:
        if self.vm.workspace_id:
            try:
                data = WorkspaceNotes(notes=self.notes.toPlainText())
            except ValidationError:
                self.message.setText("Notes exceed 100,000 characters.")
                return
            self.vm.mutate(
                "notes-save",
                "PUT",
                f"/api/v1/workspaces/{self.vm.workspace_id}/notes",
                WorkspaceNotes,
                data,
            )

    def update_state(self, key: str, value: object) -> None:
        if key == "workspaces" and isinstance(value, RootModel):
            self.workspaces.clear()
            for row in value.root:
                if isinstance(row, WorkspaceView):
                    self.workspaces.addItem(row.name + (" · active" if row.active else ""), row.id)
                    if row.active:
                        self.workspaces.setCurrentIndex(self.workspaces.count() - 1)
        elif key == "workspace" and self.vm.workspace_id:
            self.notes.clear()
            self.vm.get(
                "notes-load", f"/api/v1/workspaces/{self.vm.workspace_id}/notes", WorkspaceNotes
            )
        elif key in {"notes-load", "notes-save"} and isinstance(value, WorkspaceNotes):
            if key == "notes-load":
                self.notes.setPlainText(value.notes)
            self.message.setText("Notes loaded." if key == "notes-load" else "Notes saved.")
        elif key in {"workspace-create", "workspace-activate", "workspace-delete"}:
            self.vm.refresh_workspaces()

    def error(self, key: str, message: str) -> None:
        if key.startswith(("workspace", "notes")):
            self.message.setText(message)


class TargetsPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.selected_id: UUID | None = None
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Targets"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Address", "Hostname", "Status", "Open ports"])
        root.addWidget(self.tree)
        self.address, self.hostname, self.ports = QLineEdit(), QLineEdit(), QLineEdit()
        self.ports.setPlaceholderText(
            'Optional JSON: [{"port":80,"protocol":"tcp","service":"http"}]'
        )
        self.status = QComboBox()
        self.status.addItems([item.value for item in TargetStatus])
        self.notes = QPlainTextEdit()
        self.notes.setMaximumHeight(100)
        form = QFormLayout()
        for title, widget in (
            ("IPv4 address", self.address),
            ("Hostname", self.hostname),
            ("Status", self.status),
            ("Ports", self.ports),
            ("Notes", self.notes),
        ):
            form.addRow(title, widget)
        root.addLayout(form)
        buttons = QHBoxLayout()
        for label, method in (
            ("New", self.clear),
            ("Save", self.save),
            ("Delete", self.delete),
            ("Add CIDR", self.bulk),
            ("Import Nmap XML", self.import_nmap),
            ("Refresh", vm.targets),
            ("Use as RHOSTS", self.transfer),
        ):
            button = QPushButton(label)
            button.clicked.connect(method)
            buttons.addWidget(button)
        root.addLayout(buttons)
        export_row = QHBoxLayout()
        self.format = QComboBox()
        self.format.addItems(["json", "csv", "nmap"])
        export = QPushButton("Export targets…")
        export.clicked.connect(self.export)
        export_row.addWidget(self.format)
        export_row.addWidget(export)
        root.addLayout(export_row)
        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.message)
        self.tree.currentItemChanged.connect(self.select)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)

    def scope(self) -> str:
        return f"?workspace_id={self.vm.workspace_id}"

    def clear(self) -> None:
        self.selected_id = None
        for field in (self.address, self.hostname, self.ports):
            field.clear()
        self.notes.clear()
        self.status.setCurrentIndex(0)

    def select(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        value = current.data(0, Qt.ItemDataRole.UserRole) if current else None
        if isinstance(value, TargetView):
            self.selected_id = value.id
            self.address.setText(str(value.address))
            self.hostname.setText(value.hostname)
            self.status.setCurrentText(value.status.value)
            self.ports.setText(json.dumps([row.model_dump() for row in value.ports]))
            self.notes.setPlainText(value.notes)

    def save(self) -> None:
        if not self.vm.workspace_id:
            return
        try:
            fields = dict(
                address=self.address.text(),
                hostname=self.hostname.text(),
                status=self.status.currentText(),
                ports=json.loads(self.ports.text() or "[]"),
                notes=self.notes.toPlainText(),
            )
            if self.selected_id:
                self.vm.mutate(
                    "target-save",
                    "PATCH",
                    f"/api/v1/targets/{self.selected_id}" + self.scope(),
                    TargetView,
                    TargetUpdate.model_validate(fields),
                )
            else:
                self.vm.mutate(
                    "target-save",
                    "POST",
                    "/api/v1/targets/" + self.scope(),
                    TargetView,
                    TargetCreate.model_validate(fields),
                )
        except (ValueError, ValidationError):
            self.message.setText("Check the IPv4 address, status and ports JSON.")

    def delete(self) -> None:
        if (
            self.selected_id
            and QMessageBox.question(
                self,
                "Delete target?",
                "Delete this target and its notes?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        ):
            self.vm.mutate(
                "target-delete",
                "DELETE",
                f"/api/v1/targets/{self.selected_id}" + self.scope(),
                EmptyResponse,
            )
            self.clear()

    def bulk(self) -> None:
        cidr, accepted = QInputDialog.getText(
            self, "Add subnet", "IPv4 CIDR (maximum 256 addresses)"
        )
        if accepted:
            try:
                self.vm.mutate(
                    "target-bulk",
                    "POST",
                    "/api/v1/targets/bulk" + self.scope(),
                    RootModel[list[TargetView]],
                    TargetBulk(cidr=cidr),
                )
            except ValidationError:
                self.message.setText("Use a valid IPv4 subnet with at most 256 addresses.")

    def import_nmap(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Import Nmap XML", "", "Nmap XML (*.xml)")
        if filename:
            self.vm.upload_file(
                "target-import",
                "/api/v1/targets/import/nmap" + self.scope(),
                RootModel[list[TargetView]],
                filename,
            )

    def export(self) -> None:
        self.vm.mutate(
            "target-export",
            "POST",
            "/api/v1/targets/export-artifact"
            + self.scope()
            + "&format="
            + self.format.currentText(),
            ArtifactView,
        )

    def transfer(self) -> None:
        if self.selected_id:
            self.vm.transfer_target(self.selected_id)

    def update_state(self, key: str, value: object) -> None:
        if key == "workspace":
            self.clear()
            self.tree.clear()
            self.vm.targets()
        elif key == "targets" and isinstance(value, RootModel):
            self.tree.clear()
            for row in value.root:
                if isinstance(row, TargetView):
                    item = QTreeWidgetItem(
                        [
                            str(row.address),
                            row.hostname,
                            row.status.value,
                            ", ".join(f"{p.port}/{p.protocol}" for p in row.ports),
                        ]
                    )
                    item.setData(0, Qt.ItemDataRole.UserRole, row)
                    self.tree.addTopLevelItem(item)
        elif key in {"target-save", "target-delete", "target-bulk", "target-import"}:
            self.vm.targets()
            self.message.setText("Targets updated.")
        elif key == "target-export" and isinstance(value, ArtifactView):
            destination, _ = QFileDialog.getSaveFileName(self, "Export targets", value.name)
            if destination:
                self.vm.save_artifact(value.workspace_id, value.id, destination)
        elif key == "target-transfer":
            self.message.setText("Transferred to the selected module's RHOSTS field.")

    def error(self, key: str, message: str) -> None:
        if key.startswith("target"):
            self.message.setText(message)


class ArtifactsPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Saved artifacts"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Bytes", "SHA-256"])
        root.addWidget(self.tree)
        for label, callback in (("Refresh", self.refresh), ("Save As…", self.save)):
            button = QPushButton(label)
            button.clicked.connect(callback)
            root.addWidget(button)
        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.message)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)

    def refresh(self) -> None:
        if self.vm.workspace_id:
            self.vm.get(
                "artifacts",
                f"/api/v1/artifacts?workspace_id={self.vm.workspace_id}",
                RootModel[list[ArtifactView]],
            )

    def save(self) -> None:
        item = self.tree.currentItem()
        artifact = item.data(0, Qt.ItemDataRole.UserRole) if item else None
        if isinstance(artifact, ArtifactView):
            destination, _ = QFileDialog.getSaveFileName(self, "Save artifact", artifact.name)
            if destination:
                self.vm.save_artifact(artifact.workspace_id, artifact.id, destination)

    def update_state(self, key: str, value: object) -> None:
        if key == "workspace":
            self.tree.clear()
            self.refresh()
        elif key == "artifacts" and isinstance(value, RootModel):
            self.tree.clear()
            for artifact in value.root:
                item = QTreeWidgetItem([artifact.name, str(artifact.size_bytes), artifact.sha256])
                item.setData(0, Qt.ItemDataRole.UserRole, artifact)
                self.tree.addTopLevelItem(item)
        elif key == "artifact-saved":
            self.message.setText("Saved.")

    def error(self, key: str, message: str) -> None:
        if key.startswith("artifact"):
            self.message.setText(message)
