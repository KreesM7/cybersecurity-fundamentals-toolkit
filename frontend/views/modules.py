"""Compact module browser with metadata-driven editors and bounded output."""

from html import escape
from uuid import UUID

from pydantic import RootModel, ValidationError
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
from frontend.widgets.examples import fill_example
from frontend.widgets.module_editor import build_editor, render_options, validate_options
from frontend.widgets.presentation import LoadingSkeleton, StatusBadge, enhance
from shared.modules import (
    ModuleDetail,
    ModuleLaunch,
    ModuleLibrary,
    ModuleRun,
    ModuleSearch,
    OptionSpec,
)
from shared.workspaces import TargetTransfer, TargetView


class ModuleBrowser(QWidget):
    query: QLineEdit
    kind: QComboBox
    rank: QComboBox
    platform: QComboBox
    tree: QTreeWidget
    title: QLabel
    description: QPlainTextEdit
    favorite: QCheckBox
    saved: QComboBox
    saved_list: QListWidget
    payload: QComboBox
    advanced: QCheckBox
    form: QFormLayout
    target: QComboBox
    owned: QCheckBox
    run: QPushButton
    output: QPlainTextEdit
    steps: QTabWidget
    summary: QPlainTextEdit
    loading: LoadingSkeleton
    status_badge: StatusBadge

    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.detail: ModuleDetail | None = None
        self.library = ModuleLibrary()
        self.fields: dict[str, QWidget] = {}
        self.option_specs: dict[str, OptionSpec] = {}
        self.option_rows: dict[str, tuple[QWidget, QLabel]] = {}
        self.target_id: UUID | None = None
        self.submitting = False
        build_editor(self)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.show_error)
        QTimer.singleShot(0, vm.refresh_workspaces)
        enhance(self)

    def validate(self, *_: object) -> bool:
        return validate_options(self)

    def try_example(self) -> None:
        fill_example(self, "modules")
        self.steps.setCurrentIndex(0)

    def search(self) -> None:
        self.loading.show()
        self.status_badge.setText("Searching…")
        self.output.appendPlainText("Searching…")
        self.vm.search_modules(
            self.query.text(),
            self.kind.currentText() if self.kind.currentIndex() != 0 else "",
            self.rank.currentText() if self.rank.currentIndex() != 0 else "",
            self.platform.currentText() if self.platform.currentText() != "All platforms" else "",
        )

    def select(self, current: QTreeWidgetItem | None, previous: QTreeWidgetItem | None) -> None:
        if current:
            path = current.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(path, str):
                self.clear_form()
                self.vm.module_detail(path)

    def choose_module(self, path: str) -> None:
        self.clear_form()
        self.vm.module_detail(path)

    def select_saved(self, index: int) -> None:
        path = self.saved.itemData(index)
        if path:
            self.clear_form()
            self.vm.module_detail(str(path))

    def select_payload(self, index: int) -> None:
        path = self.payload.itemData(index)
        if self.detail:
            self.render_fields(self.detail.options)
        if path:
            self.vm.module_detail("payload/" + str(path), payload=True)

    def clear_form(self) -> None:
        self.detail = None
        self.submitting = False
        self.target_id = None
        self.owned.setChecked(False)
        self.run.setEnabled(False)
        self.favorite.setEnabled(False)
        self.render_fields([])

    def render_fields(self, fields: list[OptionSpec], *, append: bool = False) -> None:
        render_options(self, fields, append)

    def set_favorite(self, enabled: bool) -> None:
        if self.detail:
            self.vm.favorite(self.detail.path, enabled)

    def transfer(self) -> None:
        identifier = self.target.currentData()
        if isinstance(identifier, UUID):
            self.vm.transfer_target(identifier)

    def launch(self) -> None:
        if self.detail is None or self.vm.workspace_id is None or not self.validate():
            return
        values: dict[str, str | int | float | bool] = {}
        for name, widget in self.fields.items():
            if isinstance(widget, QCheckBox):
                values[name] = widget.isChecked()
            elif isinstance(widget, QComboBox):
                values[name] = widget.currentText()
            elif isinstance(widget, QLineEdit) and widget.text():
                values[name] = widget.text()
        if self.payload.currentData():
            values["PAYLOAD"] = str(self.payload.currentData())
        try:
            value = ModuleRun(
                path=self.detail.path,
                framework_id=self.detail.framework_id,
                workspace_id=self.vm.workspace_id,
                target_id=self.target_id,
                options=values,
                confirmed=self.owned.isChecked(),
            )
        except ValidationError:
            self.output.appendPlainText("Check the module fields before running.")
            return
        self.submitting = True
        self.run.setEnabled(False)
        self.output.appendPlainText(
            "Launch submitted. An uncertain command will never repeat automatically."
        )
        self.vm.launch_module(value)

    def update_state(self, key: str, value: object) -> None:
        if key == "workspace":
            self.clear_form()
            self.output.clear()
            self.vm.module_library()
            self.vm.targets()
        elif key == "module-search" and isinstance(value, ModuleSearch):
            self.loading.hide()
            self.tree.clear()
            groups: dict[str, QTreeWidgetItem] = {}
            for row in value.modules:
                group = groups.setdefault(row.kind, QTreeWidgetItem([row.kind]))
                if group.treeWidget() is None:
                    self.tree.addTopLevelItem(group)
                item = QTreeWidgetItem([row.path, row.rank])
                item.setData(0, Qt.ItemDataRole.UserRole, row.path)
                item.setToolTip(0, escape(row.name))
                group.addChild(item)
            self.tree.expandAll()
            self.status_badge.setText(
                f"{len(value.modules)} matches. Select a module to configure."
            )
            self.output.appendPlainText(
                f"{len(value.modules)} matches."
                + (" First 2,000 shown; refine your search." if value.truncated else "")
            )
        elif key == "module-detail" and isinstance(value, ModuleDetail):
            self.detail = value
            self.title.setText(value.path)
            self.description.setPlainText(value.description)
            self.favorite.blockSignals(True)
            self.favorite.setChecked(value.path in self.library.favorites)
            self.favorite.blockSignals(False)
            self.favorite.setEnabled(True)
            self.payload.clear()
            self.payload.addItem("Select payload", "")
            for path in value.payloads:
                self.payload.addItem(path, path)
            self.payload.setEnabled(bool(value.payloads))
            self.render_fields(value.options)
            self.steps.setCurrentIndex(1)
            self.validate()
        elif key == "payload-detail" and isinstance(value, ModuleDetail):
            if value.path == "payload/" + str(self.payload.currentData()):
                self.render_fields(value.options, append=True)
        elif key in {"module-library", "module-favorite"} and isinstance(value, ModuleLibrary):
            self.library = value
            self.saved.clear()
            self.saved_list.clear()
            self.saved.addItem("Favorites / recent modules", "")
            for path in value.favorites:
                self.saved.addItem("Favorite: " + path, path)
                saved_item = QListWidgetItem("Favorite: " + path)
                saved_item.setData(Qt.ItemDataRole.UserRole, path)
                self.saved_list.addItem(saved_item)
            for path in value.recent:
                self.saved.addItem("Recent: " + path, path)
                saved_item = QListWidgetItem("Recent: " + path)
                saved_item.setData(Qt.ItemDataRole.UserRole, path)
                self.saved_list.addItem(saved_item)
        elif key == "targets" and isinstance(value, RootModel):
            self.target.clear()
            for row in value.root:
                if isinstance(row, TargetView):
                    self.target.addItem(str(row.address), row.id)
        elif key == "target-transfer" and isinstance(value, TargetTransfer):
            if value.workspace_id == self.vm.workspace_id:
                field = self.fields.get("RHOSTS", self.fields.get("RHOST"))
                if isinstance(field, QLineEdit):
                    field.setText(str(value.rhosts))
                    self.target_id = value.target_id
        elif key == "module-launch" and isinstance(value, ModuleLaunch):
            self.output.appendPlainText(
                f"{value.status}: {value.path} · Framework job {value.remote_job_id or 'none'}"
            )
            self.submitting = False
            self.validate()
            self.vm.module_library()
        elif key == "event" and isinstance(value, dict) and value.get("topic") == "module-launch":
            if value.get("workspace_id") == str(self.vm.workspace_id):
                self.output.appendPlainText(str(value.get("data", {}).get("status", "")))

    def show_error(self, key: str, message: str) -> None:
        if key.startswith("module") or key in {"targets", "target-transfer", "payload-detail"}:
            self.loading.hide()
            self.status_badge.setText("Failed: " + message)
            self.output.appendPlainText(message)
            if key == "module-launch":
                self.output.appendPlainText("Check Jobs before submitting another launch.")
                self.submitting = False
            self.validate()
