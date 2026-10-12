from uuid import uuid4

import pytest
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication, QLineEdit, QTabWidget

from frontend.views.activity import ActivityPanel
from frontend.views.modules import ModuleBrowser
from frontend.views.payloads import PayloadPanel
from shared.modules import ModuleDetail, OptionSpec
from tests.v2.test_module_ui import ViewModelFixture


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application
    application.processEvents()


def test_module_review_requires_fields_and_explicit_ownership(app):
    vm = ViewModelFixture()
    panel = ModuleBrowser(vm)
    panel.update_state(
        "module-detail",
        ModuleDetail(
            path="auxiliary/scanner/test",
            framework_id=uuid4(),
            name="Fixture",
            description="Local fixture",
            options=[
                OptionSpec(name="RHOSTS", required=True),
                OptionSpec(name="PORT", kind="integer", default=80),
            ],
        ),
    )
    assert not panel.run.isEnabled()
    panel.owned.setChecked(True)
    assert not panel.run.isEnabled()
    panel.fields["RHOSTS"].setText("127.0.0.1")
    assert panel.run.isEnabled()
    assert panel.steps.count() == 3
    assert panel.fields["RHOSTS"].toolTip()
    panel.owned.setChecked(False)
    assert not panel.run.isEnabled()
    panel.deleteLater()


def test_console_is_guided_by_default_with_three_activity_tabs(app):
    panel = ActivityPanel(ViewModelFixture())
    assert [panel.tabs.tabText(i) for i in range(panel.tabs.count())] == [
        "Sessions",
        "Jobs",
        "Console",
    ]
    assert not panel.advanced.isChecked()
    assert panel.command.isHidden() or panel.command.parentWidget().isHidden()
    for timer in panel.findChildren(QTimer):
        timer.stop()
    panel.deleteLater()


def test_module_and_payload_have_run_and_guide_tabs(app):
    for cls in (ModuleBrowser, PayloadPanel):
        panel = cls(ViewModelFixture())
        assert any(
            [tabs.tabText(i) for i in range(tabs.count())] == ["Run", "Guide"]
            for tabs in panel.findChildren(QTabWidget)
        )
        for field in panel.findChildren(QLineEdit):
            assert field.toolTip()
        for timer in panel.findChildren(QTimer):
            timer.stop()
        panel.deleteLater()


def test_every_page_input_has_help_and_accessible_name_and_nine_guides(app):
    from PyQt6.QtWidgets import QAbstractButton, QAbstractSpinBox, QComboBox, QPlainTextEdit

    from frontend.main_window import MainWindow
    from tests.v2.presentation_fixture import PresentationModel

    window = MainWindow(PresentationModel())
    window.show()
    app.processEvents()
    try:
        assert len(window.page_indices) == 17
        for page, index in window.page_indices.items():
            window.navigate_title(page)
            app.processEvents()
            panel = window.stack.widget(index)
            for widget in panel.findChildren(
                (QLineEdit, QPlainTextEdit, QComboBox, QAbstractSpinBox, QAbstractButton)
            ):
                assert widget.toolTip(), (page, type(widget).__name__, widget.objectName())
                assert widget.accessibleName(), (page, type(widget).__name__)
        for panel in list(window.panels.values()) + [
            window.stack.widget(window.page_indices[k]) for k in ("Modules", "Payloads")
        ]:
            assert any(
                [tabs.tabText(i) for i in range(tabs.count())] == ["Run", "Guide"]
                for tabs in panel.findChildren(QTabWidget)
            )
        window.navigation.collapse()
        window.navigate_title("Modules")
        assert window.stack.currentIndex() == window.page_indices["Modules"]
        window.navigate_title("Settings")
        assert window.stack.currentIndex() == window.page_indices["Settings"]
    finally:
        window._closing = True
        window.close()


def test_theme_contrast_and_icon_exports(app):
    from PyQt6.QtGui import QImage

    from frontend.icons import app_icon
    from frontend.theme import PALETTES, apply_theme

    def luminance(color):
        rgb = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in rgb]
        return sum(v * weight for v, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

    for mode, tokens in PALETTES.items():
        apply_theme(app, mode)
        for foreground, background in [
            (c, b)
            for c in (
                tokens.foreground,
                tokens.muted,
                tokens.danger,
                tokens.success,
                tokens.warning,
            )
            for b in (tokens.background, tokens.surface)
        ] + [(tokens.accent_text, tokens.accent)]:
            light, dark = sorted((luminance(foreground), luminance(background)), reverse=True)
            assert (light + 0.05) / (dark + 0.05) >= 4.5, (mode, foreground, background)
        for size in (16, 32, 128):
            image = (
                app_icon().pixmap(size, size).toImage().convertToFormat(QImage.Format.Format_ARGB32)
            )
            assert image.width() == size and image.height() == size
            assert image.pixelColor(size // 2, size // 2).alpha() > 0


def test_examples_fill_without_dispatch_or_ownership(app):
    from frontend.views.tools import PANELS, create_panel
    from frontend.widgets.examples import fill_example
    from tests.v2.presentation_fixture import PresentationModel

    vm = PresentationModel()
    for key, _ in PANELS:
        panel = create_panel(key, vm)
        vm.calls.clear()
        fill_example(panel, key)
        assert not any("/run" in str(call) or "/upload" in str(call) for call in vm.calls)
        if hasattr(panel, "owned"):
            assert not panel.owned.isChecked()
        if hasattr(panel, "file_path"):
            from pathlib import Path

            assert Path(panel.file_path.text()).is_file()
        panel.deleteLater()


def test_guides_are_brief_and_have_three_to_five_steps():
    from frontend.help_text import GUIDES

    assert len(GUIDES) == 9
    for name, sections in GUIDES.items():
        assert len(sections) == 5
        assert 3 <= len(sections[2]) <= 5, name
        text = " ".join(" ".join(s) if isinstance(s, tuple) else s for s in sections)
        assert len(text.split()) <= 120, (name, len(text.split()))


def test_all_visible_controls_reachable_by_tab(app):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QTabWidget, QWidget

    from frontend.main_window import MainWindow
    from tests.v2.presentation_fixture import PresentationModel

    window = MainWindow(PresentationModel())
    window.show()
    window.activateWindow()
    app.processEvents()
    try:
        for page in window.page_indices:
            window.navigate_title(page)
            panel = window.stack.currentWidget()
            variants = [(None, 0)] + [
                (tab, i) for tab in panel.findChildren(QTabWidget) for i in range(tab.count())
            ]
            for tab, index in variants:
                if tab:
                    tab.setCurrentIndex(index)
                app.processEvents()
                targets = [
                    w
                    for w in panel.findChildren(QWidget)
                    if w.isVisible()
                    and w.isEnabled()
                    and w.focusPolicy() & Qt.FocusPolicy.TabFocus
                    and not w.focusProxy()
                ]
                window.navigation.toggle.setFocus()
                seen = set()
                for _ in range(250):
                    widget = app.focusWidget()
                    if widget is None or id(widget) in seen:
                        break
                    seen.add(id(widget))
                    QTest.keyClick(widget, Qt.Key.Key_Tab)
                    app.processEvents()
                missing = [
                    (type(w).__name__, w.accessibleName()) for w in targets if id(w) not in seen
                ]
                assert not missing, (page, index, missing)
    finally:
        window._closing = True
        window.close()


def test_saved_module_side_list_selects_exact_path(app):
    from shared.modules import ModuleLibrary
    from tests.v2.presentation_fixture import PresentationModel

    vm = PresentationModel()
    panel = ModuleBrowser(vm)
    panel.update_state(
        "module-library",
        ModuleLibrary(
            favorites=["auxiliary/scanner/favorite"], recent=["auxiliary/scanner/recent"]
        ),
    )
    vm.calls.clear()
    panel.saved_list.setCurrentRow(panel.saved_list.count() - 1)
    assert vm.calls[-1][0] == ("auxiliary/scanner/recent",)
    panel.deleteLater()


def test_guided_module_selection_resets_ownership_before_fetch(app):
    from frontend.main_window import MainWindow
    from frontend.widgets.activity_controls import guided_run, update_context
    from shared.modules import ModuleLibrary
    from tests.v2.presentation_fixture import PresentationModel

    vm = PresentationModel()
    window = MainWindow(vm)
    modules = window.stack.widget(window.page_indices["Modules"])
    activity = window.stack.widget(window.page_indices["Sessions & Jobs"])
    try:
        modules.update_state(
            "module-detail",
            ModuleDetail(
                path="auxiliary/scanner/old",
                framework_id=uuid4(),
                name="Old",
                description="Local test fixture",
                options=[OptionSpec(name="RHOSTS", required=True, default="127.0.0.1")],
            ),
        )
        modules.target_id = uuid4()
        modules.owned.setChecked(True)
        assert modules.run.isEnabled()
        update_context(activity, ModuleLibrary(favorites=["auxiliary/scanner/new"]))
        activity.context.setCurrentIndex(1)
        guided_run(activity)
        assert not modules.owned.isChecked()
        assert not modules.run.isEnabled()
        assert modules.target_id is None
        assert modules.detail is None
    finally:
        window._closing = True
        window.close()


def test_guided_stop_does_not_use_hidden_selection(app, monkeypatch):
    from PyQt6.QtWidgets import QPushButton

    from shared.activity import ActivitySnapshot, RemoteItem
    from shared.modules import ModuleLibrary
    from tests.v2.presentation_fixture import PresentationModel

    vm = PresentationModel()
    panel = ActivityPanel(vm)
    calls = []
    panel.show()
    app.processEvents()
    monkeypatch.setattr(panel, "stop", lambda: calls.append(panel.selected()))
    panel.update_state(
        "activity-snapshot",
        ActivitySnapshot(
            framework_id=uuid4(),
            workspace_id=vm.workspace_id,
            items=[
                RemoteItem(
                    remote_id="1", kind="session", name="Fixture", workspace_id=vm.workspace_id
                )
            ],
        ),
    )
    panel.update_state("module-library", ModuleLibrary(favorites=["auxiliary/scanner/test"]))
    panel.context.setCurrentIndex(1)
    panel.context.setCurrentIndex(2)
    kill = next(b for b in panel.findChildren(QPushButton) if b.text() == "Kill selected")
    assert not kill.isEnabled()
    kill.click()
    assert not calls
    panel.deleteLater()


def test_vault_indicator_preserves_dashboard_connection_state(app):
    from frontend.views.desktop import DesktopControls
    from shared.framework import ConnectionStatus
    from shared.vault import VaultStatus
    from tests.v2.presentation_fixture import PresentationModel

    vm = PresentationModel()
    panel = DesktopControls(vm)
    panel.update_state("connection-status", ConnectionStatus(state="Offline"))
    panel.update_state(
        "vault-indicator",
        VaultStatus(initialized=True, unlocked=False, workspace_id=vm.workspace_id),
    )
    assert "Offline" in panel.status.text()
    assert "Ready · Ready" not in panel.status.text()
    panel.deleteLater()


def test_table_headers_have_no_empty_overlay_and_help_icons_follow_theme(app):
    from PyQt6.QtWidgets import QHeaderView

    from frontend.theme import apply_theme
    from frontend.views.workspaces import TargetsPanel
    from frontend.widgets.presentation import HelpButton
    from tests.v2.presentation_fixture import PresentationModel

    panel = TargetsPanel(PresentationModel())
    panel.show()
    for header in panel.findChildren(QHeaderView):
        assert not header.property("emptyHelp")
    buttons = panel.findChildren(HelpButton)
    assert buttons
    apply_theme(app, "dark")
    app.processEvents()
    dark_key = buttons[0].icon().cacheKey()
    apply_theme(app, "light")
    app.processEvents()
    assert buttons[0].icon().cacheKey() != dark_key
    panel.deleteLater()
