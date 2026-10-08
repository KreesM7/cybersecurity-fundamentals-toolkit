"""Signature identification upload panel."""

from frontend.views.tools.base import FilePanel
from shared.tools import FileOptions


class Panel(FilePanel):
    tool_id, title = "file-type", "File Type Identifier"
    description = (
        "Identify MIME type and signature from at most the first 1 MiB; "
        "compare the original filename extension. Extension checks are advisory. "
        "A file signature does not establish safety."
    )

    def options(self) -> FileOptions:
        return FileOptions()
