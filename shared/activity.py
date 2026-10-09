"""Workspace/framework-scoped remote activity and terminal contracts."""

from typing import Literal

from pydantic import Field, SecretStr

from shared.schemas import Identifier, SchemaModel


class RemoteItem(SchemaModel):
    remote_id: str
    kind: Literal["session", "job"]
    name: str
    workspace_id: Identifier | None = None
    session_type: str = ""
    peer: str = ""


class ActivitySnapshot(SchemaModel):
    framework_id: Identifier
    workspace_id: Identifier
    items: list[RemoteItem]


class RemoteAction(SchemaModel):
    workspace_id: Identifier
    framework_id: Identifier
    remote_id: str = Field(pattern=r"^[0-9]{1,20}$")
    kind: Literal["session", "job"]
    confirmed: bool = False


class TerminalCommand(SchemaModel):
    workspace_id: Identifier
    framework_id: Identifier
    remote_id: str = Field(pattern=r"^[0-9]{1,20}$")
    kind: Literal["console", "shell", "meterpreter"]
    command: SecretStr = Field(max_length=65536)

    def transport_dump(self) -> dict[str, object]:
        data = self.model_dump(mode="json")
        data["command"] = self.command.get_secret_value()
        return data


class ConsoleOpen(SchemaModel):
    workspace_id: Identifier
    framework_id: Identifier


class ConsoleHandle(ConsoleOpen):
    remote_id: str


class TerminalOutput(SchemaModel):
    lines: list[str]
    sequence: int
    truncated: bool = False


class ActionResult(SchemaModel):
    status: str
