"""Pure registration for Traffic Anomaly Detector."""

from backend.jobs import JobContext
from backend.tools import ToolRuntime, ToolSpec
from shared.tools import ToolOptions
from toolkit.modules import anomaly_detector as analysis


async def run(
    runtime: ToolRuntime,
    options: ToolOptions,
    content: bytes | None,
    filename: str,
    context: JobContext,
) -> object:
    return await runtime.analyze("anomaly-detector", options, content, filename, context)


TOOL = ToolSpec(
    analysis.MODULE.id,
    analysis.MODULE.title,
    analysis.MODULE.order,
    run,
    note="CSV/log ready; saved captures require the separate PCAP worker.",
)
