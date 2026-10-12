"""Live scoped activity, explicit controls and bounded terminal output."""

from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import RootModel
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QTreeWidgetItem,
)

from frontend.widgets.activity_controls import filter_activity, update_context
from shared.activity import (
    ActivitySnapshot,
    ConsoleHandle,
    ConsoleOpen,
    RemoteItem,
    TerminalOutput,
)
from shared.framework import ConnectionStatus
from shared.modules import ModuleLibrary
from shared.tools import ToolJob

if TYPE_CHECKING:
    from frontend.views.activity import ActivityPanel


def render_activity(owner: "ActivityPanel", key: str, value: object) -> None:
    if key == "workspace":
        owner.snapshot = owner.terminal = None
        owner.library = ModuleLibrary()
        update_context(owner)
        owner._selection = None
        owner.sequence = 0
        owner._loading = owner._reading = False
        owner.tree.clear()
        owner.output.clear()
        owner.command.clear()
    elif key == "activity-snapshot" and isinstance(value, ActivitySnapshot):
        owner._loading = False
        owner.snapshot = value
        owner.connection.setText("Framework " + str(value.framework_id))
        # Preserve local rows when refreshing the remote snapshot.
        for index in reversed(range(owner.tree.topLevelItemCount())):
            item = owner.tree.topLevelItem(index)
            if item and isinstance(item.data(0, Qt.ItemDataRole.UserRole), RemoteItem):
                owner.tree.takeTopLevelItem(index)
        for row in value.items:
            item = QTreeWidgetItem(
                [
                    row.kind,
                    row.remote_id,
                    row.name,
                    row.peer,
                    "This workspace" if row.workspace_id else "Unassigned — import to control",
                ]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, row)
            owner.tree.addTopLevelItem(item)
    elif key == "activity-local" and isinstance(value, RootModel):
        for index in reversed(range(owner.tree.topLevelItemCount())):
            item = owner.tree.topLevelItem(index)
            if item and isinstance(item.data(0, Qt.ItemDataRole.UserRole), ToolJob):
                owner.tree.takeTopLevelItem(index)
        for job in value.root:
            item = QTreeWidgetItem(
                ["Local", str(job.id), job.tool_id + " · " + job.status, "", "This workspace"]
            )
            item.setData(0, Qt.ItemDataRole.UserRole, job)
            owner.tree.addTopLevelItem(item)
    elif key == "activity-connection" and isinstance(value, ConnectionStatus):
        if value.instance_id and value.state != "Offline" and owner.vm.workspace_id:
            owner.vm.mutate(
                "terminal-open",
                "POST",
                "/api/v1/activity/console",
                ConsoleHandle,
                ConsoleOpen(
                    workspace_id=owner.vm.workspace_id, framework_id=UUID(value.instance_id)
                ),
            )
    elif key == "terminal-open" and isinstance(value, ConsoleHandle):
        owner.terminal = value
        owner.terminal_kind = "console"
        owner.sequence = 0
        owner._reading = False
        owner.vm.invalidate("terminal-output")
        owner.output.clear()
        owner.read_output()
    elif key == "terminal-output" and isinstance(value, TerminalOutput):
        owner._reading = False
        owner.sequence = value.sequence
        if value.truncated:
            owner.output.appendPlainText(
                "Older terminal output was discarded at the display limit."
            )
        if value.lines:
            owner.output.appendPlainText("\n".join(value.lines))
    elif key == "terminal-history" and isinstance(value, RootModel):
        owner.output.appendPlainText("\n".join(value.root))
    elif key in {"terminal-command", "activity-action"}:
        owner.connection.setText("Action completed.")
        owner.output.appendPlainText("Action completed.")
        owner.refresh()
    elif (
        key == "event"
        and isinstance(value, dict)
        and value.get("topic") in {"activity", "module-launch"}
    ):
        owner.refresh()

    owner.restore_selection()
    filter_activity(owner)
    if key in {"activity-snapshot", "workspace"}:
        update_context(owner)
    elif key in {"module-library", "module-favorite"} and isinstance(value, ModuleLibrary):
        update_context(owner, value)
