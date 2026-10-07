"""Strict workspace and target transport contracts; no paths or credentials are exposed."""

from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from importlib import import_module
from ipaddress import IPv4Address, IPv4Network
from typing import Annotated, Literal, cast

from pydantic import Field, field_validator

from shared.schemas import Identifier, SchemaModel

# The preserved legacy module is not typed; bind only its two policy contracts.
_policy = import_module("toolkit.security")
is_target_address = cast(Callable[[IPv4Address], bool], _policy.is_target_address)
validate_subnet = cast(Callable[[str], IPv4Network], _policy.validate_subnet)

WorkspaceName = Annotated[str, Field(min_length=1, max_length=100)]
Text = Annotated[str, Field(max_length=100000)]
Hostname = Annotated[str, Field(max_length=253)]
Address = Annotated[IPv4Address, Field(strict=False)]


class WorkspaceCreate(SchemaModel):
    """Description for a workspace whose storage path comes solely from its UUID."""

    name: WorkspaceName
    description: Text = ""

    @field_validator("name")
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Workspace name must not be blank")
        return value


class WorkspaceView(WorkspaceCreate):
    """Catalog identity and currently selected state."""

    id: Identifier
    created_at: Annotated[datetime, Field(strict=False)]
    active: bool


class WorkspaceNotes(SchemaModel):
    """Workspace-local plain notes, with a bounded text payload."""

    notes: Text = ""


class TargetStatus(StrEnum):
    """User-visible progress for a target."""

    NOT_SCANNED = "not_scanned"
    OPEN = "open"
    EXPLOITED = "exploited"
    SESSION_ACTIVE = "session_active"


class OpenPort(SchemaModel):
    """One open TCP/UDP service observed on a target."""

    port: Annotated[int, Field(ge=1, le=65535)]
    protocol: Literal["tcp", "udp"]
    service: Annotated[str, Field(max_length=253)] = ""


class TargetCreate(SchemaModel):
    """Ordinary IPv4 target, hostname, observed open ports and local notes."""

    address: Address
    hostname: Hostname = ""
    ports: Annotated[list[OpenPort], Field(max_length=1024)] = Field(default_factory=list)
    status: Annotated[TargetStatus, Field(strict=False)] = TargetStatus.NOT_SCANNED
    notes: Text = ""

    @field_validator("address", mode="before")
    @classmethod
    def ordinary_ipv4(cls, value: object) -> IPv4Address:
        # Reject numeric and legacy dotted representations instead of normalizing them.
        if not isinstance(value, (str, IPv4Address)):
            raise ValueError("Use a standard dotted IPv4 address")
        address = IPv4Address(value)
        if not is_target_address(address):
            raise ValueError("Unsupported IPv4 target")
        return address


class TargetUpdate(SchemaModel):
    """Partial target edit; explicit nulls are rejected to preserve required values."""

    address: Address | None = None
    hostname: Hostname | None = None
    ports: Annotated[list[OpenPort], Field(max_length=1024)] | None = None
    status: Annotated[TargetStatus, Field(strict=False)] | None = None
    notes: Text | None = None

    @field_validator("address", mode="before")
    @classmethod
    def ordinary_ipv4(cls, value: object) -> IPv4Address:
        return TargetCreate.ordinary_ipv4(value)

    @field_validator("hostname", "ports", "status", "notes", mode="before")
    @classmethod
    def reject_null(cls, value: object) -> object:
        if value is None:
            raise ValueError("Explicit null is not a target value")
        return value


class TargetView(TargetCreate):
    """Persisted target identity with immutable workspace association and timestamps."""

    id: Identifier
    workspace_id: Identifier
    created_at: Annotated[datetime, Field(strict=False)]
    updated_at: Annotated[datetime, Field(strict=False)]


class TargetBulk(SchemaModel):
    """CIDR expanded atomically, with no more than 256 IPv4 addresses."""

    cidr: Annotated[str, Field(min_length=1, max_length=32)]

    @field_validator("cidr")
    @classmethod
    def bounded_network(cls, value: str) -> str:
        return str(validate_subnet(value))


class TargetTransfer(SchemaModel):
    """Safe event payload for transferring a selected target to a module's RHOSTS."""

    target_id: Identifier
    workspace_id: Identifier
    rhosts: Address
