"""Data-only fundamentals command parsing; execution stays in the existing job service."""

import json

from shared.tools import ToolOptions, options_adapter

FILE_TOOLS = frozenset({"dos-detector", "anomaly-detector", "file-type"})
EXAMPLES = {
    "caesar": '{"text":"Hello", "shift":3, "decrypt":false}',
    "password-strength": '{"password":"example-only"}',
    "network-scanner": '{"target":"127.0.0.1/32"}',
    "sql-checker": '{"url":"http://127.0.0.1:8000/", "operation":"discover"}',
    "dos-detector": '{"file":"examples/requests.csv", "threshold":100}',
    "anomaly-detector": '{"file":"examples/traffic.csv", "baseline_bins":30, "threshold":3}',
    "file-type": '{"file":"examples/sample.pcap"}',
}


def parse_options(tool_id: str, arguments: str) -> tuple[ToolOptions, str | None]:
    data = json.loads(arguments)
    if not isinstance(data, dict) or data.get("kind", tool_id) != tool_id:
        raise ValueError("Supply a JSON options object for the current tool.")
    filename = data.pop("file", None)
    if filename is not None and (
        tool_id not in FILE_TOOLS or not isinstance(filename, str) or not filename.strip()
    ):
        raise ValueError("Supply a file path only for file-based tools.")
    data["kind"] = tool_id
    options = options_adapter.validate_json(json.dumps(data))
    return options, filename


def command_help(tool_id: str) -> str:
    return (
        "In-app tool terminal (not a system shell)\n\n"
        "help             Show commands and an example\n"
        "run              Run with the current GUI settings\n"
        "run {JSON}       Run with explicit tool options\n"
        "cancel           Cancel this tool's current job\n"
        "clear            Clear the command and session results\n\n"
        f"Example:\nrun {EXAMPLES[tool_id]}\n\n"
        "File tools accept a file path in the JSON file field, or use the GUI file selection.\n"
        "SQL testing uses operation=test with the discovery_id, generation, form_index and\n"
        "fields returned by discovery; allow_post explicitly enables POST.\n"
        "Commands are not echoed or saved. Password commands are masked."
    )
