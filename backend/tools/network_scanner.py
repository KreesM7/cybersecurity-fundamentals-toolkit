"""Pure registration for Network Scanner."""

from backend.jobs import JobContext
from backend.tools import ToolRuntime, ToolSpec
from shared.tools import ToolOptions
from toolkit.modules import network_scanner as analysis
from toolkit.modules.network_scanner import readiness


async def run(
    runtime: ToolRuntime,
    options: ToolOptions,
    content: bytes | None,
    filename: str,
    context: JobContext,
) -> object:
    return await runtime.analyze("network-scanner", options, content, filename, context)


TOOL = ToolSpec(analysis.MODULE.id, analysis.MODULE.title, analysis.MODULE.order, run, readiness)
