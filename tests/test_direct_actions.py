"""Explicit actions work without a separate ownership declaration."""

from uuid import uuid4

from PyQt6.QtWidgets import QApplication, QCheckBox

from backend.services.async_scanner import validate_scan
from shared.secdesk import NativeLaunch
from shared.tools import ScannerOptions
from toolkit.secdesk.registry import ToolManifest, load_registry


def test_native_launch_does_not_require_acknowledgment():
    request = NativeLaunch(workspace_id=uuid4(), tool_id="tcpdump", mode="terminal")
    assert request.tool_id == "tcpdump"


def test_scan_validation_does_not_require_acknowledgment():
    validate_scan(ScannerOptions(target="127.0.0.1/32"))


def test_manifest_names_do_not_impose_policy_exclusions():
    template = load_registry()[0].model_dump()
    for identifier in ("nmap", "kali", "john", "burp"):
        assert ToolManifest.model_validate(template | {"id": identifier}).id == identifier


def test_action_panels_have_no_ownership_checkbox():
    from frontend.views.modules import ModuleBrowser
    from frontend.views.payloads import PayloadPanel
    from frontend.views.tools.network_scanner import Panel as ScannerPanel
    from frontend.views.tools.sql_checker import Panel as SQLPanel
    from frontend.widgets.native_controls import NativeControls
    from tests.v2.test_module_ui import ViewModelFixture

    app = QApplication.instance() or QApplication([])
    from PyQt6.QtCore import pyqtSignal

    class ToolFixture(ViewModelFixture):
        job_changed = pyqtSignal(str, object)
        tool_error = pyqtSignal(str, str)
        interfaces_changed = pyqtSignal(object)

    panels = [
        factory(ToolFixture())
        for factory in (ModuleBrowser, PayloadPanel, ScannerPanel, SQLPanel, NativeControls)
    ]
    try:
        for panel in panels:
            labels = [box.text().lower() for box in panel.findChildren(QCheckBox)]
            assert not any("i own" in label or "permission" in label for label in labels)
    finally:
        for panel in panels:
            panel.deleteLater()
        app.processEvents()
