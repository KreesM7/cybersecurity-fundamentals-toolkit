"""User-imported findings remain scoped to the existing workspace switcher."""

from pydantic import RootModel
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from frontend.theme import SPACE
from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.presentation import StatusBadge
from shared.secdesk import FindingImportResult, FindingSource, FindingView
from toolkit.secdesk.registry import load_registry


class FindingsPanel(QWidget):
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        layout = QVBoxLayout(self)
        layout.setSpacing(SPACE["sm"])
        self.source = QComboBox()
        self.source.setAccessibleName("Findings source tool")
        self.source.setToolTip("Choose the real tool that produced the imported findings.")
        try:
            for tool in load_registry():
                self.source.addItem(tool.name, tool.id)
        except (ValueError, OSError):
            self.source.setEnabled(False)
        layout.addWidget(self.source)
        for text, action in (
            ("Import normalized JSON / CSV", self.choose_file),
            ("Refresh workspace findings", self.refresh),
        ):
            button = QPushButton(text)
            button.setAccessibleName(text)
            button.setToolTip(text + "; no native command or scan is run.")
            button.clicked.connect(action)
            layout.addWidget(button)
        self.status = StatusBadge("Explicit imports only; export summaries through Reports")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setAccessibleName("Workspace findings inventory")
        self.output.setToolTip(
            "Latest 500 findings. Same source, title and target merge; latest evidence wins."
        )
        layout.addWidget(self.output, 1)
        self.vm.state_changed.connect(self.update_state)
        self.vm.action_error.connect(self.error)

    def choose_file(self) -> None:
        if self.vm.workspace_id is None or self.source.currentData() is None:
            return
        name, _ = QFileDialog.getOpenFileName(
            self, "Import explicit findings", "", "Findings (*.json *.csv)"
        )
        if not name:
            return
        self.vm.upload_findings(
            FindingSource(workspace_id=self.vm.workspace_id, tool_id=self.source.currentData()),
            name,
        )

    def refresh(self) -> None:
        if self.vm.workspace_id:
            self.vm.get(
                "secdesk-findings",
                f"/api/v1/secdesk/findings?workspace_id={self.vm.workspace_id}",
                RootModel[list[FindingView]],
            )

    def update_state(self, key: str, value: object) -> None:
        if key == "workspace":
            self.output.clear()
            self.refresh()
        elif key == "secdesk-findings-import" and isinstance(value, FindingImportResult):
            self.status.setText(
                f"Imported {value.inserted}; merged {value.merged}. Review before reporting."
            )
            self.refresh()
        elif key == "secdesk-findings" and isinstance(value, RootModel):
            self.output.setPlainText(
                "\n\n".join(
                    f"{row.severity.upper()} · {row.tool_id} · {row.target}\n"
                    f"{row.title}\n{row.evidence}"
                    for row in value.root
                    if isinstance(row, FindingView)
                )
                or "No findings in this workspace."
            )

    def error(self, key: str, message: str) -> None:
        if key.startswith("secdesk-findings"):
            self.status.set_status(message, "failed")
