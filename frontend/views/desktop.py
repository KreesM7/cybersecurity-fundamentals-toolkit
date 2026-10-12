"""Desktop preferences and dashboard controls using the shared asynchronous ViewModel."""

import sys

from pydantic import RootModel
from PyQt6.QtCore import Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from frontend.theme import SPACE, apply_theme
from frontend.viewmodels.app_vm import AppViewModel
from frontend.views.connection import ConnectionPanel
from frontend.widgets.presentation import StatusBadge, enhance
from shared.desktop import (
    DashboardSummary,
    DesktopSettings,
    UpdateNotice,
    UpdateProgress,
    UpdateRequest,
)
from shared.framework import ConnectionStatus
from shared.vault import VaultStatus
from shared.workspaces import WorkspaceView


class DesktopControls(QWidget):
    navigate_requested = pyqtSignal(str)
    install_requested = pyqtSignal()

    def __init__(self, vm: AppViewModel) -> None:
        super().__init__()
        self.vm = vm
        self.settings: DesktopSettings | None = None
        self.submitted: DesktopSettings | None = None
        self.notice = UpdateNotice()
        self.update_progress = UpdateProgress()
        self.owns_backend = True
        root = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Workspace"))
        self.workspace = QComboBox()
        row.addWidget(self.workspace, 1)
        self.workspace.activated.connect(self.switch_workspace)
        root.addLayout(row)
        self.counts = QLabel("Loading workspace…")
        self.status = StatusBadge("Framework offline · Vault locked")
        root.addWidget(self.counts)
        root.addWidget(self.status)
        self.welcome = QWidget()
        welcome_layout = QVBoxLayout(self.welcome)
        welcome = QLabel(
            "Start with the seven fundamentals tools. Saved captures work offline.\n"
            "Use Workspaces to organize targets and notes. Set up Toolkit-MSF before\n"
            "connecting in Settings. Test only systems you own or are permitted to assess.\n"
            "Ctrl+K: find a page · Ctrl+T: modules · Ctrl+L: console · "
            "Ctrl+S: save notes · F5: sessions"
        )
        welcome.setWordWrap(True)
        welcome_layout.addWidget(welcome)
        for title, destination in (
            ("1 · Create workspace", "Workspaces"),
            ("2 · Add target", "Targets"),
            ("3 · Run a module", "Modules"),
        ):
            step = QPushButton(title)
            step.clicked.connect(
                lambda checked=False, page=destination: self.navigate_requested.emit(page)
            )
            welcome_layout.addWidget(step)
        done = QPushButton("Got it")
        done.clicked.connect(self.finish_onboarding)
        welcome_layout.addWidget(done)
        root.addWidget(self.welcome)
        self.banner = QWidget()
        banner_layout = QVBoxLayout(self.banner)
        banner_layout.setContentsMargins(0, SPACE["sm"], 0, SPACE["sm"])
        banner_layout.setSpacing(SPACE["sm"])
        self.update_text = QLabel("")
        self.update_text.setTextFormat(Qt.TextFormat.PlainText)
        banner_layout.addWidget(self.update_text)
        self.verification = StatusBadge("Waiting for download")
        banner_layout.addWidget(self.verification)
        self.download_progress = QProgressBar()
        self.download_progress.setRange(0, 100)
        self.download_progress.setTextVisible(False)
        self.download_progress.setAccessibleName("Update download progress")
        self.download_progress.setToolTip(
            "Installer download progress. Installation requires verified checksums and signatures."
        )
        banner_layout.addWidget(self.download_progress)
        actions = QHBoxLayout()
        self.download_button = QPushButton("Download update")
        self.download_button.setProperty("role", "primary")
        self.download_button.setToolTip(
            "Download the signed installer; your current installation stays running."
        )
        self.download_button.clicked.connect(self.download_update)
        self.install_button = QPushButton("Install && restart")
        self.install_button.setToolTip(
            "After verification, close owned activity, upgrade this installation and restart."
        )
        self.install_button.setEnabled(False)
        self.install_button.clicked.connect(self.install_requested.emit)
        self.release_button = QPushButton("View release")
        self.release_button.clicked.connect(self.open_release)
        dismiss = QPushButton("Dismiss")
        dismiss.clicked.connect(self.dismiss_update)
        for button in (self.download_button, self.install_button, self.release_button, dismiss):
            actions.addWidget(button)
        actions.addStretch()
        banner_layout.addLayout(actions)
        self.banner.hide()
        self.settings_panel = QTabWidget()
        general = QWidget()
        form = QVBoxLayout(general)
        form.addWidget(QLabel("Appearance"))
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light", "system"])
        form.addWidget(self.theme)
        self.updates = QCheckBox("Check GitHub for updates on startup (no downloads)")
        form.addWidget(self.updates)
        form.addWidget(self.banner)
        self.message = StatusBadge("Loading settings…")
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        form.addWidget(self.message)
        retry = QPushButton("Retry loading settings")
        retry.clicked.connect(self.load)
        form.addWidget(retry)
        form.addStretch()
        self.settings_panel.addTab(general, "General")
        self.settings_panel.addTab(ConnectionPanel(vm), "Metasploit")
        self.theme.setEnabled(False)
        self.updates.setEnabled(False)
        self.theme.currentTextChanged.connect(self.changed)
        self.updates.toggled.connect(self.changed)
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.setInterval(400)
        self.debounce.timeout.connect(self.save)
        self.timer = QTimer(self)
        self.timer.setInterval(5000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        vm.state_changed.connect(self.update_state)
        vm.action_error.connect(self.error)
        self.load()
        enhance(self)

    def load(self) -> None:
        self.vm.get("settings-load", "/api/v1/settings", DesktopSettings)

    def changed(self) -> None:
        if self.settings:
            selected = self.theme.currentText()
            if selected == "system":
                self.settings.theme = "system"
            elif selected == "light":
                self.settings.theme = "light"
            else:
                self.settings.theme = "dark"
            self.settings.check_updates = self.updates.isChecked()
            application = QApplication.instance()
            if isinstance(application, QApplication):
                apply_theme(application, self.settings.theme)
            self.message.setText("Saving…")
            self.debounce.start()

    def save(self) -> None:
        if self.settings and self.submitted is None:
            self.submitted = self.settings.model_copy()
            self.vm.mutate(
                "settings-save", "PUT", "/api/v1/settings", DesktopSettings, self.submitted
            )

    def finish_onboarding(self) -> None:
        if self.settings:
            self.settings.onboarding_complete = True
            self.welcome.hide()
            self.debounce.start()

    def dismiss_update(self) -> None:
        if self.settings:
            self.settings.dismissed_version = self.notice.version
            self.banner.hide()
            self.debounce.start()

    def open_release(self) -> None:
        # The backend constructs a fixed public repository URL; never open arbitrary response links.
        prefix = "https://github.com/KreesM7/cybersecurity-fundamentals-toolkit/releases/tag/"
        if self.notice.version and self.notice.url == prefix + self.notice.version:
            QDesktopServices.openUrl(QUrl(self.notice.url))

    def switch_workspace(self, index: int) -> None:
        scope = self.workspace.itemData(index)
        if scope and scope != self.vm.workspace_id:
            self.vm.mutate(
                "workspace-activate", "POST", f"/api/v1/workspaces/{scope}/activate", WorkspaceView
            )

    def refresh(self) -> None:
        if self.vm.workspace_id:
            self.vm.get(
                "dashboard",
                f"/api/v1/dashboard?workspace_id={self.vm.workspace_id}",
                DashboardSummary,
            )
            self.vm.vault_request("vault-indicator", "GET", "status", VaultStatus)
        self.vm.get("connection-status", "/api/v1/connection", ConnectionStatus)
        self.vm.get("updates", "/api/v1/updates", UpdateNotice)
        self.vm.get("update-progress", "/api/v1/updates/progress", UpdateProgress)

    def update_state(self, key: str, value: object) -> None:
        if key == "settings-load" and isinstance(value, DesktopSettings):
            self.settings = value
            self.theme.blockSignals(True)
            self.updates.blockSignals(True)
            self.theme.setCurrentText(value.theme)
            self.updates.setChecked(value.check_updates)
            self.theme.blockSignals(False)
            self.updates.blockSignals(False)
            self.theme.setEnabled(True)
            self.updates.setEnabled(True)
            self.welcome.setVisible(not value.onboarding_complete)
            application = QApplication.instance()
            if isinstance(application, QApplication):
                apply_theme(application, value.theme)
            self.message.setText("Settings loaded.")
            self.refresh()
        elif key == "settings-save" and isinstance(value, DesktopSettings):
            self.submitted = None
            if self.settings != value:
                self.debounce.start()
            else:
                self.message.setText("Saved.")
            self.refresh()
        elif key == "workspaces" and isinstance(value, RootModel):
            self.workspace.clear()
            for row in value.root:
                if isinstance(row, WorkspaceView):
                    self.workspace.addItem(row.name, row.id)
                    if row.active:
                        self.workspace.setCurrentIndex(self.workspace.count() - 1)
        elif key == "workspace":
            self.counts.setText("Loading workspace…")
            self.refresh()
        elif key == "dashboard" and isinstance(value, DashboardSummary):
            self.counts.setText(
                f"{value.targets} targets · {value.recorded_sessions} recorded sessions · "
                f"{value.running_jobs} local jobs · {value.saved_reports} reports"
            )
        elif key == "updates" and isinstance(value, UpdateNotice):
            self.notice = value
            self.update_text.setText(f"Toolkit {value.version} is available.")
            self.render_update()
            self.banner.setVisible(
                bool(value.version)
                and bool(self.settings and self.settings.dismissed_version != value.version)
            )
        elif key in {"update-progress", "update-download", "update-apply"} and isinstance(
            value, UpdateProgress
        ):
            self.update_progress = value
            self.render_update()
        elif key == "event" and isinstance(value, dict) and value.get("topic") == "update-progress":
            self.update_progress = UpdateProgress.model_validate(value["data"])
            self.render_update()
        elif key in {"connection", "connection-status"} and isinstance(value, ConnectionStatus):
            self.status.setText(
                f"{value.state} · Vault {'unlocked' if self.vm.vault_token else 'locked'}"
            )
        elif key in {"vault-indicator", "vault-locked"}:
            state = self.status.raw_text.split(" · ")[0]
            unlocked = isinstance(value, VaultStatus) and value.unlocked
            self.status.setText(f"{state} · Vault {'unlocked' if unlocked else 'locked'}")

    def download_update(self) -> None:
        self.download_button.setEnabled(False)
        self.vm.mutate(
            "update-download",
            "POST",
            "/api/v1/updates/download",
            UpdateProgress,
            UpdateRequest(version=self.notice.version),
        )

    def render_update(self) -> None:
        state = self.update_progress
        windows = sys.platform == "win32"
        busy = state.phase in {"downloading", "verifying", "preparing", "prepared"}
        verified = (
            state.version == self.notice.version
            and state.phase == "verified"
            and state.checksum_verified
            and state.signature_verified
        )
        self.download_button.setVisible(windows)
        self.install_button.setVisible(windows)
        self.release_button.setVisible(not windows or not self.notice.installer_url)
        self.download_button.setEnabled(
            bool(self.notice.installer_url) and not busy and not verified
        )
        self.download_button.setText(
            "Retry download" if state.phase == "failed" else "Download update"
        )
        self.install_button.setEnabled(verified and state.can_apply and self.owns_backend)
        self.install_button.setProperty(
            "role", "primary" if self.install_button.isEnabled() else "secondary"
        )
        self.download_progress.setVisible(windows and state.phase != "idle")
        self.download_progress.setValue(min(100, state.received * 100 // max(1, state.total)))
        self.download_progress.setProperty("state", "done" if verified else "running")
        message = state.message or (
            "Ready to download"
            if self.notice.installer_url
            else "Signed installer not available for this release"
        )
        if verified:
            message = "Checksum verified · Signature verified"
            if not state.can_apply:
                message += " · Install & restart requires an installed Windows build."
            elif not self.owns_backend:
                message += " · Use the window that started the backend to install."
        self.verification.setVisible(windows)
        if state.phase == "failed":
            message = "Update failed · " + message
        self.verification.setText(message)
        for widget in (self.install_button, self.download_progress):
            style = widget.style()
            if style:
                style.unpolish(widget)
                style.polish(widget)

    def error(self, key: str, message: str) -> None:
        if key in {"update-download", "update-apply"}:
            self.update_progress = self.update_progress.model_copy(
                update={"phase": "failed", "message": "Update failed. Retry download."}
            )
            self.render_update()

        if key.startswith("settings"):
            self.submitted = None
            self.message.setText(message + " Change a setting to retry saving, or retry loading.")
