"""Compact module browser with metadata-driven editors and bounded output."""

from html import escape
from uuid import UUID

from pydantic import RootModel, ValidationError
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from frontend.viewmodels.app_vm import AppViewModel
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
    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.detail: ModuleDetail | None = None
        self.library = ModuleLibrary()
        self.fields: dict[str, QWidget] = {}
        self.target_id: UUID | None = None
        root = QVBoxLayout(self)
        root.addWidget(QLabel("Metasploit modules"))
        filters = QHBoxLayout()
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search modules; Enter to search")
        self.kind, self.rank, self.platform = QComboBox(), QComboBox(), QComboBox()
        self.kind.addItems(
            ["", "auxiliary", "exploit", "post", "payload", "encoder", "nop", "evasion"]
        )
        self.rank.addItems(["", "manual", "low", "average", "normal", "good", "great", "excellent"])
        self.platform.addItems(
            ["", "windows", "linux", "unix", "multi", "osx", "android", "java", "php"]
        )
        self.kind.setItemText(0, "All types")
        self.rank.setItemText(0, "All ranks")
        self.platform.setItemText(0, "All platforms")
        self.platform.setEditable(True)
        search = QPushButton("Search")
        for widget in (self.query, self.kind, self.rank, self.platform, search):
            filters.addWidget(widget)
        root.addLayout(filters)
        split = QSplitter()
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Module", "Rank"])
        split.addWidget(self.tree)
        right = QWidget()
        controls = QVBoxLayout(right)
        self.title = QLabel("Connect in Settings, then search or choose a saved module.")
        self.title.setTextFormat(Qt.TextFormat.PlainText)
        self.title.setWordWrap(True)
        controls.addWidget(self.title)
        self.description = QPlainTextEdit()
        self.description.setReadOnly(True)
        self.description.setMaximumHeight(110)
        controls.addWidget(self.description)
        self.favorite = QCheckBox("Favorite")
        self.favorite.setEnabled(False)
        controls.addWidget(self.favorite)
        self.saved = QComboBox()
        self.saved.addItem("Favorites / recent modules", "")
        controls.addWidget(self.saved)
        self.payload = QComboBox()
        self.payload.addItem("Payload (when applicable)", "")
        controls.addWidget(self.payload)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        form_widget = QWidget()
        self.form = QFormLayout(form_widget)
        scroll.setWidget(form_widget)
        controls.addWidget(scroll, 1)
        targets = QHBoxLayout()
        self.target = QComboBox()
        refresh = QPushButton("Refresh targets")
        transfer = QPushButton("Use as RHOSTS")
        for widget in (self.target, refresh, transfer):
            targets.addWidget(widget)
        controls.addLayout(targets)
        self.owned = QCheckBox("I own these targets or have explicit permission to test them.")
        controls.addWidget(self.owned)
        self.run = QPushButton("Run selected module")
        self.run.setEnabled(False)
        controls.addWidget(self.run)
        split.addWidget(right)
        split.setSizes([350, 600])
        root.addWidget(split, 1)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(10000)
        self.output.setMaximumHeight(140)
        root.addWidget(self.output)
        search.clicked.connect(self.search)
        self.query.returnPressed.connect(self.search)
        self.tree.currentItemChanged.connect(self.select)
        self.favorite.toggled.connect(self.set_favorite)
        self.saved.activated.connect(self.select_saved)
        self.payload.activated.connect(self.select_payload)
        refresh.clicked.connect(vm.targets)
        transfer.clicked.connect(self.transfer)
        self.run.clicked.connect(self.launch)
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.show_error)
        QTimer.singleShot(0, vm.refresh_workspaces)

    def search(self) -> None:
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
        self.target_id = None
        self.owned.setChecked(False)
        self.run.setEnabled(False)
        self.favorite.setEnabled(False)
        self.render_fields([])

    def render_fields(self, fields: list[OptionSpec], *, append: bool = False) -> None:
        if not append:
            while self.form.rowCount():
                self.form.removeRow(0)
            self.fields.clear()
        for item in fields:
            if item.name in self.fields:
                continue
            widget: QWidget
            if item.kind == "bool":
                checkbox = QCheckBox()
                checkbox.setChecked(item.default is True)
                widget = checkbox
            elif item.choices:
                combo = QComboBox()
                combo.addItems(item.choices)
                if item.default is not None:
                    combo.setCurrentText(str(item.default))
                widget = combo
            else:
                line = QLineEdit("" if item.default is None else str(item.default))
                line.setMaxLength(4096)
                if item.secret:
                    line.setEchoMode(QLineEdit.EchoMode.Password)
                widget = line
            widget.setToolTip(escape(item.description))
            self.form.addRow(item.name + (" *" if item.required else ""), widget)
            self.fields[item.name] = widget

    def set_favorite(self, enabled: bool) -> None:
        if self.detail:
            self.vm.favorite(self.detail.path, enabled)

    def transfer(self) -> None:
        identifier = self.target.currentData()
        if isinstance(identifier, UUID):
            self.vm.transfer_target(identifier)

    def launch(self) -> None:
        if self.detail is None or self.vm.workspace_id is None:
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
            self.run.setEnabled(
                value.path.split("/", 1)[0] in {"auxiliary", "exploit", "post", "evasion"}
            )
        elif key == "payload-detail" and isinstance(value, ModuleDetail):
            if value.path == "payload/" + str(self.payload.currentData()):
                self.render_fields(value.options, append=True)
        elif key in {"module-library", "module-favorite"} and isinstance(value, ModuleLibrary):
            self.library = value
            self.saved.clear()
            self.saved.addItem("Favorites / recent modules", "")
            for path in value.favorites:
                self.saved.addItem("★ " + path, path)
            for path in value.recent:
                self.saved.addItem("Recent: " + path, path)
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
            self.run.setEnabled(self.detail is not None)
            self.vm.module_library()
        elif key == "event" and isinstance(value, dict) and value.get("topic") == "module-launch":
            if value.get("workspace_id") == str(self.vm.workspace_id):
                self.output.appendPlainText(str(value.get("data", {}).get("status", "")))

    def show_error(self, key: str, message: str) -> None:
        if key.startswith("module") or key in {"targets", "target-transfer", "payload-detail"}:
            self.output.appendPlainText(message)
            if key == "module-launch":
                self.output.appendPlainText("Check Jobs before submitting another launch.")
                self.run.setEnabled(self.detail is not None)
