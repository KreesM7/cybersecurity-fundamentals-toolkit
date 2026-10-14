"""Static inspection presentation using the common owned background jobs."""

import json
from pathlib import Path

from PyQt6.QtGui import QFontDatabase
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.theme import SPACE
from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.presentation import StatusBadge, enhance
from shared.lowrea import LowreaOptions
from shared.tools import ToolJob
from toolkit.lowrea.domain import Evidence


class LowreaPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.evidence: Evidence | None = None
        self.busy = False
        self.accept_errors = False
        layout = QVBoxLayout(self)
        layout.setSpacing(SPACE["md"])
        title = QLabel("LowREA")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        description = QLabel(
            "Inspect artifact bytes, PE/ELF headers and selected instructions. "
            "Results include evidence, file offsets and analysis limits."
        )
        description.setWordWrap(True)
        layout.addWidget(description)
        row = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.file_path.setAccessibleName("Artifact file")
        self.choose_button = QPushButton("Choose file…")
        self.choose_button.clicked.connect(self.choose_file)
        self.inspect_button = QPushButton("Inspect file")
        self.inspect_button.setProperty("role", "primary")
        self.inspect_button.clicked.connect(lambda checked=False: self.inspect())
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(lambda: vm.cancel("lowrea"))
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear)
        row.addWidget(self.file_path, 1)
        for button in (
            self.choose_button,
            self.inspect_button,
            self.cancel_button,
            self.clear_button,
        ):
            row.addWidget(button)
        layout.addLayout(row)
        form = QGridLayout()
        form.setHorizontalSpacing(SPACE["md"])
        form.setVerticalSpacing(SPACE["sm"])
        form.setColumnStretch(1, 1)
        form.setColumnStretch(3, 1)
        self.architecture = QComboBox()
        self.architecture.addItems(["auto", "x86-64", "x86", "arm64"])
        self.start = QComboBox()
        self.start.addItems(["Entry point / first bytes", "File offset"])
        self.offset = QLineEdit("0x0")
        self.offset.setEnabled(False)
        self.start.currentIndexChanged.connect(lambda index: self.offset.setEnabled(index == 1))
        self.length = QSpinBox()
        self.length.setRange(1, 4096)
        self.length.setValue(256)
        self.endian = QComboBox()
        self.endian.addItems(["little", "big"])
        self.endian.setEnabled(False)
        self.architecture.currentTextChanged.connect(
            lambda text: self.endian.setEnabled(text != "auto")
        )
        for index, (name, widget) in enumerate(
            (
                ("Architecture", self.architecture),
                ("Raw byte order", self.endian),
                ("Start", self.start),
                ("File offset", self.offset),
                ("Bytes in window", self.length),
            )
        ):
            label = QLabel(name)
            label.setBuddy(widget)
            grid_row, column = divmod(index, 2)
            form.addWidget(label, grid_row, column * 2)
            form.addWidget(widget, grid_row, column * 2 + 1)
        layout.addLayout(form)
        self.status = StatusBadge("Choose an artifact to begin")
        layout.addWidget(self.status)
        self.details = QTreeWidget()
        self.details.setHeaderLabels(["Artifact detail", "Value"])
        self.details.setAccessibleName("Artifact identity and header details")
        self.details.setMaximumHeight(190)
        layout.addWidget(self.details)
        self.tabs = QTabWidget()
        self.instructions = QTreeWidget()
        self.instructions.setHeaderLabels(
            ["Address / space", "File offset", "Bytes", "Instruction"]
        )
        self.instructions.setAccessibleName("Decoded instruction window")
        self.instructions.setUniformRowHeights(True)
        self.regions = QTreeWidget()
        self.regions.setHeaderLabels(["Mapped region", "File offset", "Bytes", "Preferred address"])
        self.regions.setAccessibleName("Mapped file regions")
        self.references = QTreeWidget()
        self.references.setHeaderLabels(["Instruction", "Target", "File offset", "Possible string"])
        self.references.setAccessibleName("Limited derived data references")
        self.hex_output = QPlainTextEdit()
        self.hex_output.setReadOnly(True)
        self.hex_output.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.hex_output.setAccessibleName("Hex byte window with file offsets")
        self.evidence_output = QPlainTextEdit()
        self.evidence_output.setReadOnly(True)
        self.evidence_output.setAccessibleName("Canonical inspection evidence and limitations")
        for tab_widget, name in (
            (self.instructions, "Instructions"),
            (self.hex_output, "Hex"),
            (self.regions, "Headers"),
            (self.references, "References"),
            (self.evidence_output, "Evidence"),
        ):
            self.tabs.addTab(tab_widget, name)
        layout.addWidget(self.tabs, 1)
        actions = QHBoxLayout()
        self.export_button = QPushButton("Export evidence…")
        self.export_button.clicked.connect(self.export)
        self.previous_button = QPushButton("Previous window")
        self.next_button = QPushButton("Next window")
        self.previous_button.clicked.connect(lambda: self.move_window(-1))
        self.next_button.clicked.connect(lambda: self.move_window(1))
        for button in (self.previous_button, self.next_button, self.export_button):
            actions.addWidget(button)
        actions.addStretch()
        layout.addLayout(actions)
        vm.job_changed.connect(self.job_changed)
        vm.tool_error.connect(self.error)
        vm.state_changed.connect(self.update_state)
        self.update_buttons()
        enhance(self)
        self.file_path.setPlaceholderText("Choose an executable or raw binary")
        self.offset.setPlaceholderText("0x1000 or 4096")
        self.architecture.setToolTip(
            "Auto uses parsed PE/ELF machine fields. Raw modes are caller-declared."
        )
        self.length.setToolTip(
            "Inspect 1–4096 bytes per window. Use Next/Previous for other ranges."
        )

    def update_buttons(self) -> None:
        self.inspect_button.setEnabled(
            bool(self.file_path.text()) and self.vm.workspace_id is not None and not self.busy
        )
        self.choose_button.setEnabled(not self.busy)
        self.cancel_button.setEnabled(self.busy)
        for button in (self.previous_button, self.next_button, self.export_button):
            button.setEnabled(self.evidence is not None and not self.busy)

    def choose_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, "Choose artifact")
        if filename:
            self.clear()
            self.file_path.setText(filename)
            self.status.set_status("Ready to inspect the selected artifact", "ready")
            self.update_buttons()

    def inspect(self, expected: str | None = None) -> None:
        if self.busy or not self.file_path.text() or self.vm.workspace_id is None:
            return
        try:
            options = LowreaOptions.model_validate(
                {
                    "architecture": self.architecture.currentText(),
                    "endian": self.endian.currentText(),
                    "offset": (
                        int(self.offset.text(), 0) if self.start.currentIndex() == 1 else None
                    ),
                    "length": self.length.value(),
                    "expected_sha256": expected,
                }
            )
        except ValueError:
            self.status.set_status(
                "Invalid offset: use a decimal or 0x hexadecimal file offset.", "failed"
            )
            return
        self.busy = True
        self.accept_errors = True
        self.update_buttons()
        self.status.set_status("Uploading and inspecting artifact…", "running")
        self.vm.inspect_lowrea(options, self.file_path.text())

    def job_changed(self, tool_id: str, value: object) -> None:
        if (
            tool_id != "lowrea"
            or not isinstance(value, ToolJob)
            or value.workspace_id != self.vm.workspace_id
        ):
            return
        self.busy = value.status in {"queued", "running", "cancelling"}
        state = {"queued": "running", "cancelling": "running", "succeeded": "done"}.get(
            value.status, value.status
        )
        self.status.set_status(value.error or value.progress or value.status.capitalize(), state)
        if value.status == "succeeded" and isinstance(value.result, dict):
            error = value.result.get("error")
            if isinstance(error, dict):
                self.status.set_status(str(error.get("message", "Inspection failed")), "failed")
            else:
                try:
                    self.show_evidence(Evidence.from_record(value.result))
                except ValueError:
                    self.status.set_status(
                        "Evidence validation failed. Inspect the artifact again.", "failed"
                    )
        self.update_buttons()

    def error(self, tool_id: str, message: str) -> None:
        if tool_id == "lowrea" and self.accept_errors:
            self.busy = False
            self.status.set_status(message, "failed")
            self.update_buttons()

    def reset_views(self) -> None:
        self.evidence = None
        for tree in (self.details, self.instructions, self.regions, self.references):
            tree.clear()
        self.hex_output.clear()
        self.evidence_output.clear()
        self.update_buttons()

    def clear(self) -> None:
        self.vm.clear("lowrea")
        self.busy = self.accept_errors = False
        self.file_path.clear()
        self.reset_views()
        self.status.set_status("Cleared. Choose an artifact to begin.", "idle")

    def update_state(self, key: str, value: object) -> None:
        if key == "workspace":
            # Completed/running jobs retain their own workspace; never display them in another.
            self.busy = self.accept_errors = False
            self.file_path.clear()
            self.reset_views()
            self.status.set_status(
                "Workspace changed. Choose an artifact for this workspace.", "idle"
            )

    def show_evidence(self, evidence: Evidence) -> None:
        record = evidence.record()
        facts = record.get("normalized_result")
        if not isinstance(facts, dict):
            raise ValueError("Expected structured inspection facts")
        headers = facts.get("headers")
        if not isinstance(headers, dict):
            raise ValueError("Expected header facts")
        self.reset_views()
        self.evidence = evidence
        for name, value in (
            ("Artifact", facts.get("filename")),
            ("SHA-256", record.get("subject_sha256")),
            ("Bytes", facts.get("size")),
            ("Header format", headers.get("format")),
            ("Header architecture", headers.get("architecture")),
            ("Preferred entry point", headers.get("entrypoint")),
        ):
            item = QTreeWidgetItem([name, str(value) if value is not None else "Unknown"])
            item.setToolTip(1, item.text(1))
            self.details.addTopLevelItem(item)
        for field, tree, keys in (
            ("instructions", self.instructions, ("address", "file_offset", "bytes", "mnemonic")),
            ("regions", self.regions, ("name", "file_offset", "size", "preferred_address")),
            (
                "references",
                self.references,
                ("instruction_address", "target_address", "file_offset", "possible_string"),
            ),
        ):
            rows = facts.get(field)
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        values = [
                            str(row.get(k)) if row.get(k) is not None else "Unknown" for k in keys
                        ]
                        if field == "instructions":
                            values[0] += " / " + str(row.get("address_space"))
                            values[-1] += " " + str(row.get("operands", ""))
                        item = QTreeWidgetItem(values)
                        for index, text in enumerate(values):
                            item.setToolTip(index, text)
                        tree.addTopLevelItem(item)
        window = facts.get("window")
        raw_hex = window.get("hex") if isinstance(window, dict) else None
        if isinstance(window, dict) and isinstance(raw_hex, str):
            data = bytes.fromhex(raw_hex)
            offset = window.get("offset")
            if isinstance(offset, int):
                lines = []
                for at in range(0, len(data), 16):
                    block = data[at : at + 16]
                    ascii_text = "".join(chr(b) if 32 <= b < 127 else "." for b in block)
                    lines.append(f"{offset+at:08x}  {block.hex(' '):47}  {ascii_text}")
                self.hex_output.setPlainText("\n".join(lines))
        self.evidence_output.setPlainText(json.dumps(record, indent=2, ensure_ascii=False))
        self.status.set_status(
            "Inspection complete · selected window · limitations in Evidence", "done"
        )
        for tree in (self.details, self.instructions, self.regions, self.references):
            for column in range(tree.columnCount()):
                tree.resizeColumnToContents(column)
        self.update_buttons()

    def move_window(self, direction: int) -> None:
        if self.evidence is None or self.busy:
            return
        record = self.evidence.record()
        facts = record.get("normalized_result")
        if not isinstance(facts, dict):
            return
        window = facts.get("window")
        if not isinstance(window, dict):
            return
        offset, size, sha = window.get("offset"), facts.get("size"), record.get("subject_sha256")
        if isinstance(offset, int) and isinstance(size, int) and isinstance(sha, str):
            target = max(0, min(size, offset + direction * self.length.value()))
            self.start.setCurrentIndex(1)
            self.offset.setText(hex(target))
            self.inspect(sha)

    def export(self) -> None:
        if self.evidence is None:
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Export inspection evidence", "lowrea-evidence.json", "JSON (*.json)"
        )
        if filename:
            try:
                Path(filename).write_text(
                    json.dumps(self.evidence.record(), indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                self.status.set_status("Evidence exported", "done")
            except OSError:
                self.status.set_status(
                    "Could not export evidence. Choose a writable destination.", "failed"
                )
