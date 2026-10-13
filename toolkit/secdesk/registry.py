"""Validated tool manifests and passive checks; never start processes or services."""

from __future__ import annotations

import os
import shutil
from importlib.resources import files
from pathlib import Path, PureWindowsPath
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Detection(Contract):
    binary: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]+$")
    version_flag: str
    windows_program_files_path: str = ""

    @field_validator("windows_program_files_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PureWindowsPath(value)
        if path.is_absolute() or path.drive or path.root or ".." in path.parts:
            raise ValueError("Program Files location must be a relative path")
        return value


class RegistryIndex(Contract):
    required_ids: list[str] = Field(min_length=1)

    @field_validator("required_ids")
    @classmethod
    def validate_identifiers(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value) or any(not item for item in value):
            raise ValueError("Required identifiers must be unique and nonempty")
        return value


class Command(Contract):
    cmd: str
    explain: str
    verification: Literal["official-docs", "real-run", "unverified"]


class Example(Contract):
    cmd: str
    output: str
    annotations: list[str]
    why: str
    verified: bool


class ErrorEntry(Contract):
    pattern: str
    cause: str
    fix: str
    doc_link: str


class ToolManifest(Contract):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    name: str
    category: str
    one_liner: str
    has_gui: bool
    native_gui: bool = False
    console: bool = False
    embedded_pages: list[str] = Field(default_factory=list)
    compatibility: str = "unknown"
    has_terminal: bool
    terminal_recommended: bool
    terminal_binary: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]+$")
    detect: Detection
    required_services: list[str]
    required_permissions: list[str]
    license: str | None
    overview: str
    setup_steps: list[str]
    commands: list[Command]
    example_success: Example
    example_failure: Example
    errors: list[ErrorEntry]
    docs_link: str
    install_link: str

    @field_validator("docs_link", "install_link")
    @classmethod
    def validate_link(cls, value: str) -> str:
        url = urlsplit(value)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("A credential-free HTTPS vendor link is required")
        return value

    @model_validator(mode="after")
    def validate_scope(self) -> ToolManifest:
        if self.terminal_recommended and not self.has_terminal:
            raise ValueError("Terminal recommendation requires a terminal interface")
        for error in self.errors:
            self.validate_link(error.doc_link)
        for example in (self.example_success, self.example_failure):
            if example.verified and not example.output:
                raise ValueError("Verified examples require captured output")
        return self


class Check(Contract):
    tool_id: str
    setup_tool_id: str = ""
    status: Literal["ready", "needs_setup", "not_installed", "license_issue"]
    binary_path: str = ""
    version: str = "unknown"
    license_status: Literal["Licensed", "Trial", "Expired", "Not detected"] = "Not detected"
    reason: str
    remediation: str


def load_registry(directory: Path | None = None) -> list[ToolManifest]:
    root = directory if directory is not None else files("toolkit.secdesk").joinpath("manifests")
    index = RegistryIndex.model_validate_json(
        files("toolkit.secdesk").joinpath("registry.json").read_text(encoding="utf8")
    )
    result = []
    identifiers: set[str] = set()
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if not path.name.endswith(".json"):
            continue
        tool = ToolManifest.model_validate_json(path.read_text(encoding="utf8"))
        if tool.id in identifiers:
            raise ValueError(f"Duplicate tool identifier: {tool.id}")
        identifiers.add(tool.id)
        result.append(tool)
    missing = set(index.required_ids) - identifiers
    if missing:
        raise ValueError(f"Required tool manifests missing: {', '.join(sorted(missing))}")
    return result


def locate_binary(tool: ToolManifest, *, terminal: bool = False) -> str | None:
    """Resolve only the requested interface, without executing the binary."""
    binary = tool.terminal_binary if terminal else tool.detect.binary
    if binary is None:
        return None
    located = shutil.which(binary)
    if not located and os.name == "nt" and tool.detect.windows_program_files_path:
        candidate = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        candidate = candidate / tool.detect.windows_program_files_path
        if terminal and binary != tool.detect.binary:
            candidate = candidate.with_name(binary + ".exe")
        located = str(candidate) if candidate.is_file() else None
    return located


def doctor(tool: ToolManifest) -> Check:
    if tool.detect.binary is None:
        return Check(
            tool_id=tool.id,
            status="needs_setup",
            reason=(
                "Managed console installation, service and license are unknown; "
                "configure your vendor console explicitly."
            ),
            remediation="Review the vendor Setup instructions. No endpoint was contacted.",
        )
    located = locate_binary(tool) or (
        locate_binary(tool, terminal=True) if tool.has_terminal else None
    )
    if not located:
        return Check(
            tool_id=tool.id,
            status="not_installed",
            reason=f"{tool.detect.binary} was not found. No installation was attempted.",
            remediation="Use the official install link, then recheck the environment.",
        )
    return Check(
        tool_id=tool.id,
        status="needs_setup",
        binary_path=located,
        reason="Binary found; version, permissions, services and license remain unverified.",
        remediation="Review Setup before explicitly launching or checking this tool.",
    )


class Guide(Contract):
    id: str
    title: str
    text: str
    docs_link: str
    install_link: str
    detect_usb: bool = False

    @field_validator("docs_link", "install_link")
    @classmethod
    def valid_link(cls, value: str) -> str:
        return ToolManifest.validate_link(value)


def load_guides() -> list[Guide]:
    from pydantic import TypeAdapter

    adapter = TypeAdapter(list[Guide])
    result = adapter.validate_json(
        files("toolkit.secdesk").joinpath("guides.json").read_text(encoding="utf8")
    )
    if {guide.id for guide in result} != {"burp", "companion"} or len(result) != 2:
        raise ValueError("Required educational guides missing or duplicated")
    return result


def prerequisites() -> list[Check]:
    from backend.platform_utils import find_nmap_binary
    from toolkit.secdesk.companion import ports

    result = []
    try:
        found = find_nmap_binary()
        result.append(
            Check(
                tool_id="Nmap dependency",
                setup_tool_id="metasploit",
                status="ready" if found else "not_installed",
                reason=(
                    "Binary located; no scan started." if found else "Nmap executable not found."
                ),
                remediation="Install Nmap from its official source; add its directory to PATH.",
            )
        )
    except ValueError:
        result.append(
            Check(
                tool_id="Nmap dependency",
                setup_tool_id="metasploit",
                status="needs_setup",
                reason="Explicit Nmap path is invalid.",
                remediation="Correct TOOLKIT_NMAP and review Metasploit Setup.",
            )
        )
    result.append(
        Check(
            tool_id="Managed services",
            setup_tool_id="metasploit",
            status="needs_setup",
            reason="Service health unknown; none started or contacted.",
            remediation="Use Metasploit Settings or explicitly open your licensed console.",
        )
    )
    result.append(
        Check(
            tool_id="Capture permissions",
            setup_tool_id="wireshark",
            status="needs_setup",
            reason="Capture and monitor-mode permissions remain unverified.",
            remediation="Review adapter, driver and privilege requirements before capture.",
        )
    )
    try:
        count = len(ports())
        reason = f"{count} serial ports observed; companion identity and protocol unknown."
    except (ImportError, OSError):
        reason = "Serial metadata unavailable; check permissions and the serial runtime."
    result.append(
        Check(
            tool_id="Device companion",
            status="needs_setup",
            reason=reason,
            remediation="Supply firmware protocol and USB VID/PID. No port was opened.",
        )
    )
    return result
