"""Pure registration for Password Strength."""

from backend.jobs import JobContext
from backend.tools import ToolRuntime, ToolSpec
from shared.tools import ToolOptions
from toolkit.modules import password_strength as analysis
from toolkit.modules.password_strength import readiness


async def run(
    runtime: ToolRuntime,
    options: ToolOptions,
    content: bytes | None,
    filename: str,
    context: JobContext,
) -> object:
    return await runtime.analyze("password-strength", options, content, filename, context)


TOOL = ToolSpec(analysis.MODULE.id, analysis.MODULE.title, analysis.MODULE.order, run, readiness)
