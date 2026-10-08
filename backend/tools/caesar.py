"""Pure registration for Caesar Cipher."""

from backend.jobs import JobContext
from backend.tools import ToolRuntime, ToolSpec
from shared.tools import ToolOptions
from toolkit.modules import caesar as analysis


async def run(
    runtime: ToolRuntime,
    options: ToolOptions,
    content: bytes | None,
    filename: str,
    context: JobContext,
) -> object:
    return await runtime.analyze("caesar", options, content, filename, context)


TOOL = ToolSpec(analysis.MODULE.id, analysis.MODULE.title, analysis.MODULE.order, run)
