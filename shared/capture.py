"""Strict, bounded version-one JSONL capture protocol; never trust worker text."""

import json
from ipaddress import ip_address
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, field_validator

from shared.schemas import SchemaModel
from toolkit.traffic import TrafficData, TrafficEvent

MAX_LINE = 65536
MAX_RECORDS = 250000
MAX_STDOUT = MAX_RECORDS * 512 + MAX_LINE
Count = Annotated[int, Field(ge=0, le=MAX_RECORDS)]
Index = Annotated[int, Field(ge=1, le=MAX_RECORDS + 1)]


class Meta(SchemaModel):
    v: Literal[1]
    type: Literal["meta"]
    unit: Literal["packets"]


class Packet(SchemaModel):
    v: Literal[1]
    type: Literal["packet"]
    index: Index
    timestamp: Annotated[float, Field(ge=-62135596800, lt=253402300800, allow_inf_nan=False)]
    source_ip: Annotated[str, Field(max_length=45)]
    bytes: Annotated[int, Field(ge=0, le=4294967295)]
    protocol: Annotated[
        str,
        Field(pattern=r"^(TCP|UDP|ICMP|IP-(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$"),
    ]

    @field_validator("source_ip")
    @classmethod
    def canonical_ip(cls, value: str) -> str:
        if "%" in value or str(ip_address(value)) != value:
            raise ValueError("Expected canonical IP address")
        return value


class Error(SchemaModel):
    v: Literal[1]
    type: Literal["error"]
    code: Literal[
        "MALFORMED_CAPTURE", "INVALID_PACKET", "INPUT_LIMIT", "MISSING_DEPENDENCY", "IO_ERROR"
    ]
    message: Annotated[str, Field(min_length=1, max_length=200)]
    index: Index
    fatal: bool


class End(SchemaModel):
    v: Literal[1]
    type: Literal["end"]
    emitted: Count
    ignored_non_ip: Count
    malformed: Count
    complete: bool


Record = Annotated[Meta | Packet | Error | End, Field(discriminator="type")]
_record: TypeAdapter[Record] = TypeAdapter(Record)
ERROR_MESSAGES = {
    "MALFORMED_CAPTURE": "Capture framing is malformed or truncated.",
    "INVALID_PACKET": "A capture packet could not be decoded.",
    "INPUT_LIMIT": "Capture input reached a configured limit.",
    "MISSING_DEPENDENCY": "Separate capture worker requires Scapy 2.8.0. See SCAPY_WORKER.md.",
    "IO_ERROR": "Capture input could not be read.",
}


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate wire key")
        result[key] = value
    return result


class CaptureProtocol:
    def __init__(self) -> None:
        self.data = TrafficData(unit="packets")
        self.meta = False
        self.end: End | None = None
        self.index = 0
        self.errors = 0
        self.fatal = False
        self.invalid = False
        self.used = 0

    def feed(self, line: bytes) -> None:
        try:
            self._feed(line)
        except (ValueError, UnicodeError):
            self.invalid = True
            raise ValueError("Invalid capture worker protocol") from None

    def _feed(self, line: bytes) -> None:
        self.used += len(line)
        if self.invalid or self.end or len(line) > MAX_LINE or self.used > MAX_STDOUT:
            raise ValueError("Wire limit/order")
        if not line.endswith(b"\n") or line.endswith(b"\r\n"):
            raise ValueError("Expected LF framing")
        raw = json.loads(line.decode("utf-8"), object_pairs_hook=_unique)
        if not isinstance(raw, dict) or type(raw.get("v")) is not int or raw["v"] != 1:
            raise ValueError("Wire version")
        row = _record.validate_python(raw)
        if isinstance(row, Meta):
            if self.meta:
                raise ValueError("Duplicate meta")
            self.meta = True
        elif not self.meta:
            raise ValueError("Missing meta")
        elif isinstance(row, End):
            count = row.emitted + row.ignored_non_ip + row.malformed
            if (
                row.emitted != len(self.data.events)
                or row.malformed != self.errors
                or count > MAX_RECORDS
                or self.index > count + int(self.fatal)
                or row.complete
                and (self.fatal or self.errors)
            ):
                raise ValueError("Inconsistent end")
            self.end = row
            self.data.skipped = row.malformed
            self.data.complete = row.complete
        elif self.fatal or row.index <= self.index:
            raise ValueError("Invalid record order")
        elif isinstance(row, Packet):
            if len(self.data.events) >= MAX_RECORDS:
                raise ValueError("Event limit")
            self.index = row.index
            self.data.events.append(
                TrafficEvent(row.timestamp, row.source_ip, row.bytes, row.protocol)
            )
        else:
            self.index = row.index
            self.fatal = row.fatal
            self.errors += int(row.code in {"MALFORMED_CAPTURE", "INVALID_PACKET"})
            if len(self.data.warnings) < 10:
                self.data.warnings.append(ERROR_MESSAGES[row.code])

    def finish(self, returncode: int) -> TrafficData:
        if (
            self.invalid
            or not self.meta
            or self.end is None
            or returncode != (0 if self.end.complete else 2)
        ):
            self.data.complete = False
            self.data.warnings.append(
                "Capture worker ended with an incomplete or invalid response."
            )
        if any(a.timestamp > b.timestamp for a, b in zip(self.data.events, self.data.events[1:])):
            self.data.warnings.append("Input was out of order; events were sorted by timestamp.")
        self.data.events.sort(key=lambda event: event.timestamp)
        return self.data
