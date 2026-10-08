"""Validate framing incrementally before bounded Scapy packet decoding."""

from __future__ import annotations

import importlib
import ipaddress
import json
import math
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any, BinaryIO, TextIO

MAX_BYTES = 25 * 1024 * 1024
MAX_RECORDS = 250000
MESSAGES = {
    "MALFORMED_CAPTURE": "Capture record is truncated or malformed",
    "INVALID_PACKET": "Capture packet is invalid",
    "INPUT_LIMIT": "Capture input limit reached",
    "MISSING_DEPENDENCY": "Scapy 2.8.0 is required",
    "IO_ERROR": "Capture input could not be read",
}


class FramingError(ValueError):
    pass


class InputLimitError(ValueError):
    pass


class WorkerCancelledError(Exception):
    pass


@dataclass(frozen=True)
class Frame:
    timestamp: float | None
    payload: bytes
    wire: int
    link: int


def _read(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise FramingError()
    return data


def _options(body: bytes, endian: str) -> dict[int, bytes]:
    options: dict[int, bytes] = {}
    offset = 0
    while offset < len(body):
        if len(body) - offset < 4:
            raise FramingError()
        code, length = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if code == 0:
            if length != 0 or any(body[offset:]):
                raise FramingError()
            break
        padded = (length + 3) & ~3
        if offset + padded > len(body):
            raise FramingError()
        options[code] = body[offset : offset + length]
        offset += padded
    return options


def frames(source: BinaryIO, max_records: int = MAX_RECORDS) -> Iterator[Frame]:
    length = source.seek(0, 2)
    source.seek(0)
    if length > MAX_BYTES:
        raise InputLimitError()
    magic = _read(source, 4)
    orders = {
        b"\xd4\xc3\xb2\xa1": ("<", 10**6),
        b"\xa1\xb2\xc3\xd4": (">", 10**6),
        b"\x4d\x3c\xb2\xa1": ("<", 10**9),
        b"\xa1\xb2\x3c\x4d": (">", 10**9),
    }
    count = 0
    if magic in orders:
        endian, resolution = orders[magic]
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", _read(source, 20))
        if (major, minor) != (2, 4) or not snaplen or link & 0xFFFF0000:
            raise FramingError()
        while source.tell() < length:
            if count >= max_records:
                raise InputLimitError()
            seconds, fraction, captured, wire = struct.unpack(endian + "IIII", _read(source, 16))
            if (
                fraction >= resolution
                or captured > wire
                or captured > snaplen
                or captured > length - source.tell()
            ):
                raise FramingError()
            count += 1
            yield Frame(seconds + fraction / resolution, _read(source, captured), wire, link)
        return
    if magic != b"\x0a\x0d\x0d\x0a":
        raise FramingError()
    source.seek(0)
    endian = ""
    interfaces: list[tuple[int, int, float, int]] = []
    blocks = 0
    while source.tell() < length:
        if blocks >= MAX_RECORDS:
            raise InputLimitError()
        blocks += 1
        start = source.tell()
        header = _read(source, 12)
        section = header[:4] == magic
        if section:
            endian = {b"\x4d\x3c\x2b\x1a": "<", b"\x1a\x2b\x3c\x4d": ">"}.get(header[8:12], "")
        if not endian:
            raise FramingError()
        kind, size = struct.unpack(endian + "II", header[:8])
        if size < (28 if section else 12) or size % 4 or size > length - start:
            raise FramingError()
        source.seek(start + size - 4)
        if struct.unpack(endian + "I", _read(source, 4))[0] != size:
            raise FramingError()
        source.seek(start + 8)
        body = _read(source, size - 12)
        source.seek(start + size)
        if section:
            if struct.unpack_from(endian + "HH", body, 4) != (1, 0):
                raise FramingError()
            _options(body[16:], endian)
            interfaces.clear()
        elif kind == 1:
            if len(body) < 8:
                raise FramingError()
            link, reserved, snaplen = struct.unpack_from(endian + "HHI", body)
            if reserved or not snaplen:
                raise FramingError()
            opts = _options(body[8:], endian)
            resolution_option = opts.get(9, b"\x06")
            offset_option = opts.get(14, b"\0" * 8)
            if len(resolution_option) != 1 or len(offset_option) != 8:
                raise FramingError()
            exponent = resolution_option[0]
            scale = float((2 if exponent & 128 else 10) ** (exponent & 127))
            interfaces.append((link, snaplen, scale, struct.unpack(endian + "q", offset_option)[0]))
        elif kind in {2, 3, 6}:
            if count >= max_records:
                raise InputLimitError()
            if kind == 3:
                if len(body) < 4 or not interfaces:
                    raise FramingError()
                interface, high, low = 0, 0, 0
                wire = struct.unpack_from(endian + "I", body)[0]
                captured = min(wire, interfaces[0][1])
                prefix = 4
            else:
                if len(body) < 20:
                    raise FramingError()
                if kind == 2:
                    interface, _ = struct.unpack_from(endian + "HH", body)
                else:
                    interface = struct.unpack_from(endian + "I", body)[0]
                high, low, captured, wire = struct.unpack_from(endian + "IIII", body, 4)
                prefix = 20
            if interface >= len(interfaces):
                raise FramingError()
            link, snaplen, scale, offset = interfaces[interface]
            end = prefix + ((captured + 3) & ~3)
            if captured > wire or captured > snaplen or end > len(body):
                raise FramingError()
            if kind == 3 and end != len(body):
                raise FramingError()
            if kind != 3:
                _options(body[end:], endian)
            count += 1
            yield Frame(
                None if kind == 3 else ((high << 32) + low) / scale + offset,
                body[prefix : prefix + captured],
                wire,
                link,
            )


def emit(output: TextIO, kind: str, **fields: object) -> None:
    output.write(
        json.dumps({"v": 1, "type": kind, **fields}, separators=(",", ":"), allow_nan=False) + "\n"
    )
    output.flush()


def decode(source: BinaryIO, output: TextIO, max_records: int = MAX_RECORDS) -> int:
    emitted = ignored = malformed = index = 0
    complete = True
    status = 0
    emit(output, "meta", unit="packets")

    def error(code: str, fatal: bool) -> None:
        emit(output, "error", code=code, message=MESSAGES[code], index=index + 1, fatal=fatal)

    try:
        scapy: Any = importlib.import_module("scapy.all")
        if importlib.import_module("scapy").__version__ != "2.8.0":
            raise ImportError()
        for frame in frames(source, max_records):
            try:
                if (
                    frame.timestamp is None
                    or not math.isfinite(frame.timestamp)
                    or not -62135596800 <= frame.timestamp < 253402300800
                ):
                    raise ValueError()
                decoder = scapy.conf.l2types.get(frame.link)
                if decoder is None:
                    raise ValueError()
                if frame.link == 1 and len(frame.payload) < 14:
                    raise ValueError()
                packet = decoder(frame.payload)
                layer = packet.getlayer(scapy.IP) or packet.getlayer(scapy.IPv6)
                if layer is None:
                    if getattr(packet, "type", None) in {0x800, 0x86DD}:
                        raise ValueError()
                    ignored += 1
                else:
                    header = bytes(layer)
                    minimum = int(layer.ihl) * 4 if layer.version == 4 else 40
                    if minimum < 20 or len(header) < minimum:
                        raise ValueError()
                    source_ip = str(ipaddress.ip_address(layer.src))
                    number = int(layer.proto if layer.version == 4 else layer.nh)
                    protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(number, f"IP-{number}")
                    emit(
                        output,
                        "packet",
                        index=index + 1,
                        timestamp=frame.timestamp,
                        source_ip=source_ip,
                        bytes=frame.wire,
                        protocol=protocol,
                    )
                    emitted += 1
            except (ValueError, TypeError, AttributeError, struct.error):
                error("INVALID_PACKET", False)
                malformed += 1
                complete = False
            index += 1
    except ImportError:
        error("MISSING_DEPENDENCY", True)
        complete, status = False, 1
    except FramingError:
        error("MALFORMED_CAPTURE", True)
        malformed += 1
        complete = False
    except InputLimitError:
        error("INPUT_LIMIT", True)
        complete = False
    except OSError:
        error("IO_ERROR", True)
        complete, status = False, 1
    except WorkerCancelledError:
        complete, status = False, 130
    except Exception:
        error("IO_ERROR", True)
        complete, status = False, 1
    finally:
        emit(
            output,
            "end",
            emitted=emitted,
            ignored_non_ip=ignored,
            malformed=malformed,
            complete=complete,
        )
    return status or (0 if complete else 2)
