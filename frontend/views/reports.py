"""Generate reports without accepting templates, external resources or storage paths."""

from uuid import UUID

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from shared.reports import ReportRequest
from shared.tools import EmptyResponse, ToolJob


class ReportsPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.job: ToolJob | None = None
        self.polling = False
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Workspace reports"))
        self.title = QLineEdit("Workspace assessment")
        self.title.setMaxLength(200)
        root.addWidget(self.title)
        self.format = QComboBox()
        self.format.addItems(["html", "pdf"])
        root.addWidget(self.format)
        self.notes = QCheckBox("Include workspace notes (review for sensitive text before sharing)")
        root.addWidget(self.notes)
        root.addWidget(QLabel("Summary only. Credentials and raw command outputs are excluded."))
        self.generate_button = QPushButton("Generate report")
        self.generate_button.clicked.connect(self.generate)
        root.addWidget(self.generate_button)
        self.cancel = QPushButton("Cancel")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.stop)
        root.addWidget(self.cancel)
        self.save = QPushButton("Save As…")
        self.save.setEnabled(False)
        self.save.clicked.connect(self.save_as)
        root.addWidget(self.save)
        self.message = QLabel("")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        self.message.setWordWrap(True)
        root.addWidget(self.message)
        root.addStretch()
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)

    def generate(self) -> None:
        if self.vm.workspace_id and self.title.text().strip():
            self.generate_button.setEnabled(False)
            self.save.setEnabled(False)
            self.vm.mutate(
                "report-start",
                "POST",
                "/api/v1/reports/generate",
                ToolJob,
                ReportRequest(
                    workspace_id=self.vm.workspace_id,
                    title=self.title.text(),
                    format="pdf" if self.format.currentText() == "pdf" else "html",
                    include_notes=self.notes.isChecked(),
                ),
            )

    def poll(self) -> None:
        if self.job and self.job.status in {"queued", "running", "cancelling"} and not self.polling:
            self.polling = True
            self.vm.get(
                "report-job",
                f"/api/v1/jobs/{self.job.id}?workspace_id={self.job.workspace_id}",
                ToolJob,
            )

    def stop(self) -> None:
        if self.job:
            self.vm.mutate(
                "report-cancel",
                "POST",
                f"/api/v1/jobs/{self.job.id}/cancel?workspace_id={self.job.workspace_id}",
                EmptyResponse,
            )

    def save_as(self) -> None:
        if self.job and isinstance(self.job.result, dict) and self.job.result.get("artifact_id"):
            path, _ = QFileDialog.getSaveFileName(self, "Save report", str(self.job.result["name"]))
            if path:
                self.vm.save_artifact(
                    self.job.workspace_id, UUID(str(self.job.result["artifact_id"])), path
                )

    def update_state(self, key: str, value: object) -> None:
        if key in {"report-start", "report-job"} and isinstance(value, ToolJob):
            self.polling = False
            self.job = value
            running = value.status in {"queued", "running", "cancelling"}
            self.cancel.setEnabled(running)
            self.generate_button.setEnabled(not running)
            self.save.setEnabled(value.status == "succeeded")
            message = value.result.get("message") if isinstance(value.result, dict) else None
            self.message.setText(str(message or value.error or value.progress or value.status))
        elif key == "artifact-saved":
            self.message.setText("Saved.")

    def error(self, key: str, message: str) -> None:
        if key.startswith("report"):
            self.polling = False
            self.message.setText(message)
            if key == "report-start":
                self.generate_button.setEnabled(True)
