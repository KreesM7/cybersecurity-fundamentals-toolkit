"""Immutable, content-addressed evidence independent of engines and transports."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator


class _Provider(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    id: str = Field(min_length=1)
    version: str | None


class _Payload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    schema_version: Literal[1]
    operation: str = Field(min_length=1)
    subject_sha256: str | None = Field(pattern=r"^[a-f0-9]{64}$")
    provider: _Provider
    confidence: Literal["observed", "derived", "inferred"]
    authority: Literal["analyst-inference", "shipped-artifact"]
    parameters: JsonValue
    normalized_result: JsonValue
    limitations: list[str]


class Evidence(BaseModel):
    """Canonical serialized facts prevent mutation through nested containers."""

    model_config = ConfigDict(frozen=True, strict=True, extra="forbid")
    canonical_json: str

    @field_validator("canonical_json")
    @classmethod
    def validate_payload(cls, value: str) -> str:
        def unique_pairs(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
            result: dict[str, JsonValue] = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON field")
                result[key] = item
            return result

        data = json.loads(value, object_pairs_hook=unique_pairs)
        if not isinstance(data, dict) or type(data.get("schema_version")) is not int:
            raise ValueError("Invalid evidence schema")
        payload = _Payload.model_validate(data)
        return cls._serialize(payload.model_dump(mode="json"))

    @classmethod
    def create(
        cls,
        operation: str,
        normalized_result: JsonValue,
        *,
        subject_sha256: str | None = None,
        confidence: Literal["observed", "derived", "inferred"] = "observed",
        provider_id: str = "builtin",
        provider_version: str | None = None,
        parameters: JsonValue = None,
        limitations: tuple[str, ...] = (),
    ) -> Evidence:
        if not operation or not provider_id:
            raise ValueError("Operation and provider identity are required")
        if subject_sha256 is not None and not re.fullmatch(r"[a-f0-9]{64}", subject_sha256):
            raise ValueError("Invalid SHA-256 subject identity")
        record: dict[str, JsonValue] = {
            "schema_version": 1,
            "operation": operation,
            "subject_sha256": subject_sha256,
            "provider": {"id": provider_id, "version": provider_version},
            "confidence": confidence,
            "authority": "analyst-inference" if confidence == "inferred" else "shipped-artifact",
            "parameters": parameters,
            "normalized_result": normalized_result,
            "limitations": list(limitations),
        }
        return cls(canonical_json=cls._serialize(record))

    @staticmethod
    def _serialize(record: dict[str, JsonValue]) -> str:
        return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)

    @property
    def evidence_id(self) -> str:
        return "ev:" + hashlib.sha256(self.canonical_json.encode("utf-8")).hexdigest()

    def record(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = json.loads(self.canonical_json)
        result["evidence_id"] = self.evidence_id
        return result

    @classmethod
    def from_record(cls, record: dict[str, JsonValue]) -> Evidence:
        data = dict(record)
        supplied = data.pop("evidence_id", None)
        evidence = cls(canonical_json=cls._serialize(data))
        if supplied != evidence.evidence_id:
            raise ValueError("Evidence digest mismatch")
        if data.get("schema_version") != 1:
            raise ValueError("Unsupported evidence schema")
        return evidence
