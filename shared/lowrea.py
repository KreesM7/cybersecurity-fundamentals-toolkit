"""Explicit static-inspection inputs. Addresses and file offsets are distinct."""

from typing import Literal
from uuid import UUID

from pydantic import Field

from shared.schemas import SchemaModel


class LowreaOptions(SchemaModel):
    kind: Literal["lowrea"] = "lowrea"
    architecture: Literal["auto", "x86", "x86-64", "arm64"] = "auto"
    endian: Literal["little", "big"] = "little"
    offset: int | None = Field(default=None, ge=0, le=2**63 - 1)
    length: int = Field(default=256, ge=1, le=4096)
    base_address: int = Field(default=0, ge=0, le=2**64 - 1)
    expected_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    workspace_id: UUID | None = Field(default=None, strict=False)
