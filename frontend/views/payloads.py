"""Metadata-backed generator, cancellable jobs, progress and managed Save As."""

from urllib.parse import urlencode
from uuid import UUID

from pydantic import ValidationError
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from frontend.help_text import option_help
from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.examples import fill_example
from frontend.widgets.presentation import enhance, explain, guide_tabs
from shared.modules import ModuleDetail, ModuleSearch
from shared.payloads import PayloadCatalog, PayloadRequest
from shared.tools import EmptyResponse, ToolJob


class PayloadPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.detail: ModuleDetail | None = None
        self.job: ToolJob | None = None
        self.artifact_id: UUID | None = None
        self._polling = False
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Payload generator · dedicated installed msfvenom"))
        row = QHBoxLayout()
        self.search = QLineEdit()
        find = QPushButton("Find payloads")
        row.addWidget(self.search)
        row.addWidget(find)
        root.addLayout(row)
        form = QFormLayout()
        self.payload, self.format, self.encoder = QComboBox(), QComboBox(), QComboBox()
        self.host = QLineEdit("127.0.0.1")
        self.port, self.iterations = QSpinBox(), QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(4444)
        self.iterations.setRange(1, 10)
        for name, widget in (
            ("Payload", self.payload),
            ("Format", self.format),
            ("LHOST", self.host),
            ("LPORT", self.port),
            ("Encoder", self.encoder),
            ("Iterations", self.iterations),
        ):
            form.addRow(name, widget)
        root.addLayout(form)
        self.owned = QCheckBox("I will use this only on systems I own or have permission to test.")
        root.addWidget(self.owned)
        row = QHBoxLayout()
        self.generate, self.cancel, self.save = (
            QPushButton("Generate"),
            QPushButton("Cancel"),
            QPushButton("Save As…"),
        )
        self.cancel.setEnabled(False)
        self.save.setEnabled(False)
        for button in (self.generate, self.cancel, self.save):
            row.addWidget(button)
        root.addLayout(row)
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        root.addWidget(self.progress)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(10000)
        root.addWidget(self.output, 1)
        find.clicked.connect(self.search_payloads)
        self.payload.activated.connect(self.select_payload)
        self.generate.clicked.connect(self.start)
        self.cancel.clicked.connect(self.stop)
        self.save.clicked.connect(self.save_as)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        self.timer = QTimer(self)
        self.timer.setInterval(500)
        self.timer.timeout.connect(self.poll)
        self.timer.start()
        self.guide_tabs = guide_tabs(self, "payloads", lambda: fill_example(self, "payloads"))
        enhance(self)

    def search_payloads(self) -> None:
        self.vm.get(
            "generator-search",
            "/api/v1/modules/search?" + urlencode({"query": self.search.text(), "kind": "payload"}),
            ModuleSearch,
        )
        self.vm.get("generator-catalog", "/api/v1/payloads/catalog", PayloadCatalog)

    def select_payload(self, index: int) -> None:
        self.detail = None
        path = self.payload.itemData(index)
        if path:
            self.vm.get(
                "generator-detail",
                "/api/v1/modules/info?" + urlencode({"path": path}),
                ModuleDetail,
            )

    def start(self) -> None:
        if not self.detail or not self.vm.workspace_id:
            self.output.appendPlainText("Connect, find a payload, and select it before generating.")
            return
        try:
            data = PayloadRequest(
                workspace_id=self.vm.workspace_id,
                framework_id=self.detail.framework_id,
                payload=self.detail.path.removeprefix("payload/"),
                format=self.format.currentText(),
                encoder=str(self.encoder.currentData() or ""),
                iterations=self.iterations.value(),
                lhost=self.host.text(),
                lport=self.port.value(),
                confirmed=self.owned.isChecked(),
            )
        except ValidationError:
            self.output.appendPlainText("Check the generation fields.")
            return
        self.generate.setEnabled(False)
        self.save.setEnabled(False)
        self.artifact_id = None
        self.progress.setRange(0, 0)
        self.vm.mutate("generator-start", "POST", "/api/v1/payloads/generate", ToolJob, data)

    def poll(self) -> None:
        if (
            self.job
            and self.job.status in {"queued", "running", "cancelling"}
            and not self._polling
        ):
            self._polling = True
            self.vm.get(
                "generator-job",
                f"/api/v1/jobs/{self.job.id}?workspace_id={self.job.workspace_id}",
                ToolJob,
            )

    def stop(self) -> None:
        if self.job:
            self.vm.mutate(
                "generator-cancel",
                "POST",
                f"/api/v1/jobs/{self.job.id}/cancel?workspace_id={self.job.workspace_id}",
                EmptyResponse,
            )

    def save_as(self) -> None:
        if self.artifact_id and self.job:
            path, _ = QFileDialog.getSaveFileName(
                self, "Save generated payload", "payload." + self.format.currentText()
            )
            if path:
                self.vm.save_artifact(self.job.workspace_id, self.artifact_id, path)

    def update_state(self, key: str, value: object) -> None:
        if key == "generator-search" and isinstance(value, ModuleSearch):
            self.payload.clear()
            for row in value.modules:
                self.payload.addItem(row.path.removeprefix("payload/"), row.path)
            if self.payload.count():
                self.select_payload(0)
        elif key == "generator-catalog" and isinstance(value, PayloadCatalog):
            self.format.clear()
            self.format.addItems(value.formats)
            self.format.setCurrentText("raw")
            self.encoder.clear()
            self.encoder.addItem("None", "")
            for path in value.encoders:
                self.encoder.addItem(path, path)
        elif key == "generator-detail" and isinstance(value, ModuleDetail):
            if value.path == self.payload.currentData():
                self.detail = value
                editors = {"LHOST": self.host, "LPORT": self.port}
                for option in value.options:
                    if option.name in editors:
                        explain(editors[option.name], option_help(option))
                self.output.appendPlainText(value.description)
        elif key in {"generator-start", "generator-job", "generator-cancel"} and isinstance(
            value, ToolJob
        ):
            self._polling = False
            self.job = value
            running = value.status in {"queued", "running", "cancelling"}
            self.cancel.setEnabled(running)
            self.generate.setEnabled(not running)
            if not running:
                self.progress.setRange(0, 1)
                self.progress.setValue(1 if value.status == "succeeded" else 0)
                self.output.appendPlainText(value.error or value.status)
                if isinstance(value.result, dict) and value.result.get("artifact_id"):
                    self.artifact_id = UUID(str(value.result["artifact_id"]))
                    self.save.setEnabled(True)
        elif key == "event" and isinstance(value, dict) and self.job:
            data = value.get("data")
            if (
                value.get("topic") == "jobs"
                and isinstance(data, dict)
                and data.get("id") == str(self.job.id)
            ):
                if data.get("progress"):
                    self.output.appendPlainText(str(data["progress"]))
        elif key == "artifact-saved" and isinstance(value, EmptyResponse):
            self.output.appendPlainText("Artifact saved.")
        elif key == "workspace":
            self.detail = None
            self.owned.setChecked(False)

    def error(self, key: str, message: str) -> None:
        if key.startswith("generator") or key == "artifact-saved":
            self._polling = False
            self.output.appendPlainText(message)
            if key == "generator-start":
                self.generate.setEnabled(True)
                self.progress.setRange(0, 1)
