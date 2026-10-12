"""Signature identification upload panel."""

from frontend.help_text import TOOL_DESCRIPTIONS
from frontend.views.tools.base import FilePanel
from shared.tools import FileOptions


class Panel(FilePanel):
    tool_id, title = "file-type", "File Type Identifier"
    description = TOOL_DESCRIPTIONS["file-type"]

    def options(self) -> FileOptions:
        return FileOptions()
