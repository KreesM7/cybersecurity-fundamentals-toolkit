"""Strict transport models without application or GUI dependencies."""

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, JsonValue, SecretStr

Identifier = Annotated[UUID, Field(strict=False)]
IPv4 = Annotated[IPv4Address, Field(strict=False)]
Name = Annotated[str, Field(min_length=1, max_length=200)]


class SchemaModel(BaseModel):
    """Reject unknown properties and implicit primitive coercion at boundaries."""

    model_config = ConfigDict(extra="forbid", from_attributes=True, strict=True)


class HealthResponse(SchemaModel):
    """Identity and readiness of the authenticated local backend instance."""

    schema_version: Literal[1] = 1
    version: Literal["2.0.0"] = "2.0.0"
    instance_id: Name
    status: Literal["ready"] = "ready"


class ErrorResponse(SchemaModel):
    """Safe structured error payload; details contain no credentials."""

    schema_version: Literal[1] = 1
    code: Name
    message: str
    details: dict[str, JsonValue] = Field(default_factory=dict)


class ToolReadiness(SchemaModel):
    """Actual capability status reported by the backend."""

    tool_id: Name
    available: bool
    reason: str | None = None


class JobStatus(StrEnum):
    """Lifecycle states of an asynchronous job."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobView(SchemaModel):
    """Public job state and ordinary JSON result."""

    id: Identifier
    module_id: Name
    status: Annotated[JobStatus, Field(strict=False)]
    created_at: datetime
    result: JsonValue = None
    error: ErrorResponse | None = None


class WorkspaceCreate(SchemaModel):
    """User supplied workspace description."""

    name: Name
    description: str = ""


class WorkspaceView(WorkspaceCreate):
    """Persisted workspace identity and description."""

    id: Identifier


class TargetCreate(SchemaModel):
    """Named IPv4 target within a workspace."""

    address: IPv4
    name: Name
    description: str = ""


class TargetUpdate(SchemaModel):
    """Optional changes to an existing IPv4 target."""

    address: IPv4 | None = None
    name: Name | None = None
    description: str | None = None


class TargetView(TargetCreate):
    """Persisted target linked to its workspace."""

    id: Identifier
    workspace_id: Identifier


class ModuleOption(SchemaModel):
    """Typed option metadata used to render a module form."""

    name: Name
    label: Name
    kind: Literal["string", "integer", "number", "boolean", "ipv4", "file", "secret"]
    required: bool = False
    default: JsonValue = None
    choices: list[str] = Field(default_factory=list)


class ModuleMetadata(SchemaModel):
    """Module presentation and capability information from the API."""

    id: Name
    title: Name
    description: str
    readiness: ToolReadiness
    options: list[ModuleOption] = Field(default_factory=list)


class ModuleRun(SchemaModel):
    """Validated transport envelope for a module execution request."""

    module_id: Name
    workspace_id: Identifier | None = None
    target_id: Identifier | None = None
    options: dict[str, JsonValue] = Field(default_factory=dict)
    secrets: dict[str, SecretStr] = Field(default_factory=dict, exclude=True, repr=False)


class ConfigSettings(SchemaModel):
    """Public settings with RPC credentials excluded from serialization."""

    theme: Literal["system", "dark", "light"] = "system"
    rpc_host: IPv4 = IPv4Address("127.0.0.1")
    rpc_port: Annotated[int, Field(ge=1, le=65535)] = 55553
    rpc_username: str = "msf"
    rpc_password: SecretStr | None = Field(default=None, exclude=True, repr=False)


class ArtifactMetadata(SchemaModel):
    """Download metadata; filesystem paths never cross the API boundary."""

    id: Identifier
    job_id: Identifier
    name: Name
    media_type: Name
    size_bytes: Annotated[int, Field(ge=0)]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
