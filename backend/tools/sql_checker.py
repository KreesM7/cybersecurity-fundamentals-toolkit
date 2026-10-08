"""Pure registration for SQL Injection Checker."""

from backend.jobs import JobContext
from backend.tools import ToolRuntime, ToolSpec
from shared.tools import ToolOptions
from toolkit.modules import sql_checker as analysis
from toolkit.modules.sql_checker import readiness


async def run(
    runtime: ToolRuntime,
    options: ToolOptions,
    content: bytes | None,
    filename: str,
    context: JobContext,
) -> object:
    return await runtime.analyze("sql-checker", options, content, filename, context)


TOOL = ToolSpec(analysis.MODULE.id, analysis.MODULE.title, analysis.MODULE.order, run, readiness)
