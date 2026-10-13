"""Explicit normalized findings imports. Terminal output is never guessed into findings."""

import csv
import io
import json
from typing import Literal

from pydantic import Field, TypeAdapter

from toolkit.secdesk.registry import Contract


class FindingRecord(Contract):
    title: str = Field(min_length=1, max_length=200)
    severity: Literal["info", "low", "medium", "high", "critical"]
    target: str = Field(min_length=1, max_length=200)
    evidence: str = Field(default="", max_length=8192, repr=False)


def read_findings(data: bytes, suffix: str) -> list[FindingRecord]:
    if len(data) > 5 * 1024 * 1024:
        raise ValueError("Findings import exceeds 5 MiB")
    text = data.decode("utf-8-sig")
    if suffix.lower() == ".json":
        try:
            records = json.loads(text, object_pairs_hook=_unique_keys)
        except (RecursionError, json.JSONDecodeError) as error:
            raise ValueError("Malformed findings JSON") from error
    elif suffix.lower() == ".csv":
        reader = csv.DictReader(io.StringIO(text), strict=True)
        if reader.fieldnames != ["title", "severity", "target", "evidence"]:
            raise ValueError("CSV columns must be title,severity,target,evidence")
        records = []
        try:
            for number, row in enumerate(reader, 2):
                if number > 1001 or None in row or None in row.values():
                    raise ValueError(f"Invalid or oversized findings CSV at row {number}")
                records.append(row)
        except csv.Error as error:
            raise ValueError("Malformed findings CSV") from error
    else:
        raise ValueError("Use a normalized JSON or CSV findings file")
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise ValueError("Import 1 to 1000 explicit findings")
    return TypeAdapter(list[FindingRecord]).validate_python(records, strict=True)


def _unique_keys(items: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate findings JSON property")
        result[key] = value
    return result
