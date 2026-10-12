"""Workspace, target and artifact forms, backed only by typed API actions."""

from pydantic import RootModel
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFileDialog,
    QLabel,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.presentation import StatusBadge, enhance
from shared.payloads import ArtifactView


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
        self.message = StatusBadge("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        root.addWidget(self.message)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        enhance(self)

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
