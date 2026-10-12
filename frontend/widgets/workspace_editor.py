"""Workspace, target and artifact forms, backed only by typed API actions."""

from pydantic import RootModel, ValidationError
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.presentation import StatusBadge, enhance, input_dialog
from shared.tools import EmptyResponse
from shared.workspaces import (
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
        self.message = StatusBadge("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.message)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        enhance(self)

    def create_workspace(self) -> None:
        name, accepted = input_dialog(self, "Create workspace", "Name", "workspace_name")
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
