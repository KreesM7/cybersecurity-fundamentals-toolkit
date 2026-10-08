"""Pure registration for File Type Identifier."""

from backend.jobs import JobContext
from backend.tools import ToolRuntime, ToolSpec
from shared.tools import ToolOptions
from toolkit.modules import file_type as analysis
from toolkit.modules.file_type import readiness


async def run(
    runtime: ToolRuntime,
    options: ToolOptions,
    content: bytes | None,
    filename: str,
    context: JobContext,
) -> object:
    return await runtime.analyze("file-type", options, content, filename, context)


TOOL = ToolSpec(analysis.MODULE.id, analysis.MODULE.title, analysis.MODULE.order, run, readiness)
