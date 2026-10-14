"""Fundamentals command consoles use existing jobs without shell execution or secret echo."""

import pytest
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import QLineEdit

from frontend.views.tools import PANELS, create_panel
from frontend.views.tools.base import ToolPanel
from tests.v2.test_module_ui import ViewModelFixture


class ToolFixture(ViewModelFixture):
    job_changed = pyqtSignal(str, object)
    tool_error = pyqtSignal(str, str)
    interfaces_changed = pyqtSignal(object)


@pytest.mark.parametrize("tool_id,title", PANELS)
def test_every_fundamentals_panel_has_visible_terminal_button(tool_id, title):
    panel = create_panel(tool_id, ToolFixture())
    try:
        assert isinstance(panel, ToolPanel)
        assert panel.terminal_button.text() == "Open in Terminal"
        assert panel.terminal_button.isVisibleTo(panel)
        panel.terminal_button.click()
        assert not panel.terminal_controls.isHidden()
        assert panel.gui_controls.isHidden()
        panel.command.setText("help")
        panel.execute_command()
        assert "run" in panel.output.toPlainText()
        panel.terminal_button.click()
        assert not panel.gui_controls.isHidden()
        assert panel.terminal_controls.isHidden()
    finally:
        panel.deleteLater()


@pytest.mark.parametrize(
    "tool_id,arguments",
    [
        ("caesar", '{"text":"Abc", "shift":3}'),
        ("password-strength", '{"password":"temporary-input"}'),
        ("network-scanner", '{"target":"127.0.0.1/32"}'),
        ("dos-detector", '{"file":"path with spaces.csv", "threshold":100}'),
        ("sql-checker", '{"url":"http://127.0.0.1:8000/"}'),
        ("anomaly-detector", '{"file":"traffic.csv", "baseline_bins":2}'),
        ("file-type", '{"file":"signature.png"}'),
    ],
)
def test_console_submits_typed_existing_job(tool_id, arguments):
    vm = ToolFixture()
    panel = create_panel(tool_id, vm)
    try:
        panel.command.setText("run " + arguments)
        panel.execute_command()
        operation, values = vm.calls[-1]
        assert operation == "submit"
        assert values[0].kind == tool_id
        if tool_id in {"dos-detector", "anomaly-detector", "file-type"}:
            assert values[1]
        assert panel.command.text() == ""
        assert "temporary-input" not in panel.output.toPlainText()
        assert "temporary-input" not in panel.status.text()
    finally:
        panel.deleteLater()


def test_password_console_masks_and_clears_rejected_secret():
    vm = ToolFixture()
    panel = create_panel("password-strength", vm)
    try:
        assert panel.command.echoMode() == QLineEdit.EchoMode.Password
        panel.command.setText('run {"password":"private-input", "invalid":true}')
        panel.execute_command()
        assert not any(call[0] == "submit" for call in vm.calls)
        assert panel.command.text() == ""
        assert "private-input" not in panel.status.text() + panel.output.toPlainText()
    finally:
        panel.deleteLater()


def test_console_help_cancel_clear_and_invalid_commands():
    vm = ToolFixture()
    panel = create_panel("caesar", vm)
    try:
        panel.command.setText("cancel")
        panel.execute_command()
        assert vm.calls[-1] == ("cancel", ("caesar",))
        panel.command.setText("clear")
        panel.execute_command()
        assert panel.output.toPlainText() == ""
        for command in ("unknown", "run []", 'run {"kind":"file-type"}', 'run {"shift":0}'):
            panel.command.setText(command)
            panel.execute_command()
        assert not any(call[0] == "submit" for call in vm.calls)
    finally:
        panel.deleteLater()


def test_sql_console_discovery_survives_clear_and_target_change():
    from uuid import uuid4

    vm = ToolFixture()
    panel = create_panel("sql-checker", vm)
    try:
        panel.clear()
        panel.url.setText("http://127.0.0.1:8001/")
        panel.command.setText('run {"url":"http://127.0.0.1:8002/"}')
        panel.execute_command()
        operation, values = vm.calls[-1]
        assert operation == "submit"
        options = values[0]
        assert options.generation == panel.target_generation
        assert options.url == panel.url.text() == "http://127.0.0.1:8002/"
        identifier = uuid4()
        panel.show_result(
            {
                "discovery_id": str(identifier),
                "generation": options.generation,
                "source_url": options.url,
                "forms": [],
            }
        )
        assert panel.discovery_id == identifier
        assert str(identifier) in panel.output.toPlainText()
    finally:
        panel.deleteLater()
