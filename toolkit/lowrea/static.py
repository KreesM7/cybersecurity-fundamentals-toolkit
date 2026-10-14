"""Limited PE/ELF header mapping and selected-window disassembly, never execution."""

from __future__ import annotations

import hashlib
import importlib
import json
import re
import struct
from dataclasses import dataclass, field
from typing import Any

from pydantic import JsonValue

from shared.lowrea import LowreaOptions
from toolkit.lowrea.domain import Evidence
from toolkit.task_context import TaskContext


@dataclass(frozen=True)
class Region:
    name: str
    offset: int
    size: int
    address: int
    executable: bool


@dataclass
class Layout:
    format: str = "unknown"
    architecture: str = "unknown"
    bits: int | None = None
    endian: str = "little"
    entry: int | None = None
    regions: list[Region] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def file_address(self, offset: int) -> int | None:
        matches = {
            r.address + offset - r.offset
            for r in self.regions
            if r.offset <= offset < r.offset + r.size
        }
        return next(iter(matches)) if len(matches) == 1 else None

    def file_offset(self, address: int) -> int | None:
        matches = {
            r.offset + address - r.address
            for r in self.regions
            if r.address <= address < r.address + r.size
        }
        return next(iter(matches)) if len(matches) == 1 else None


def _bounds(data: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(data) - size:
        raise ValueError("Header or mapped file range exceeds the captured artifact.")


def _number(data: bytes, offset: int, kind: str, endian: str = "little") -> int:
    prefix = "<" if endian == "little" else ">"
    _bounds(data, offset, struct.calcsize(prefix + kind))
    return int(struct.unpack_from(prefix + kind, data, offset)[0])


def _region(data: bytes, name: str, offset: int, size: int, address: int, execute: bool) -> Region:
    _bounds(data, offset, size)
    if address < 0 or address + size > 2**64:
        raise ValueError("Mapped virtual address range overflows 64 bits.")
    return Region(name, offset, size, address, execute)


def _pe(data: bytes, layout: Layout) -> None:
    layout.format = "DOS/MZ"
    position = _number(data, 0x3C, "I")
    _bounds(data, position, 24)
    if data[position : position + 4] != b"PE\x00\x00":
        raise ValueError("PE signature is missing at the declared header offset.")
    layout.format = "PE"
    machine, count = _number(data, position + 4, "H"), _number(data, position + 6, "H")
    optional, optional_size = position + 24, _number(data, position + 20, "H")
    _bounds(data, optional, optional_size)
    magic = _number(data, optional, "H")
    if magic not in (0x10B, 0x20B) or optional_size < (96 if magic == 0x10B else 112):
        raise ValueError("PE optional header is truncated or unsupported.")
    layout.bits = 32 if magic == 0x10B else 64
    architecture, bits = {0x14C: ("x86", 32), 0x8664: ("x86-64", 64), 0xAA64: ("arm64", 64)}.get(
        machine, ("unknown", layout.bits)
    )
    if bits != layout.bits:
        raise ValueError("PE machine and optional-header bitness disagree.")
    layout.architecture = architecture
    base = _number(
        data, optional + (28 if layout.bits == 32 else 24), "I" if layout.bits == 32 else "Q"
    )
    layout.entry = base + _number(data, optional + 16, "I")
    if layout.entry >= 2**64 or count > 96:
        raise ValueError("PE entry address or section count is not loader-valid.")
    table = optional + optional_size
    _bounds(data, table, count * 40)
    regions = []
    for index in range(count):
        at = table + index * 40
        name = data[at : at + 8].rstrip(b"\x00").decode("ascii", "backslashreplace")
        virtual_size, rva = _number(data, at + 8, "I"), _number(data, at + 12, "I")
        size, offset = _number(data, at + 16, "I"), _number(data, at + 20, "I")
        _bounds(data, offset, size)
        if size:
            regions.append(
                _region(
                    data,
                    name,
                    offset,
                    min(size, virtual_size or size),
                    base + rva,
                    bool(_number(data, at + 36, "I") & 0x20000000),
                )
            )
    layout.regions = regions


def _elf(data: bytes, layout: Layout) -> None:
    layout.format = "ELF"
    _bounds(data, 0, 16)
    if data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        raise ValueError("ELF class, byte order or identification version is unsupported.")
    layout.bits, layout.endian = (32 if data[4] == 1 else 64), ("little" if data[5] == 1 else "big")
    end = layout.endian
    _bounds(data, 0, 52 if layout.bits == 32 else 64)
    layout.architecture = {3: "x86", 62: "x86-64", 183: "arm64"}.get(
        _number(data, 18, "H", end), "unknown"
    )
    if _number(data, 20, "I", end) != 1:
        raise ValueError("ELF header version is unsupported.")
    wide = layout.bits == 64
    layout.entry = _number(data, 24, "Q" if wide else "I", end)
    table = _number(data, 32 if wide else 28, "Q" if wide else "I", end)
    header_size = _number(data, 52 if wide else 40, "H", end)
    step = _number(data, 54 if wide else 42, "H", end)
    count = _number(data, 56 if wide else 44, "H", end)
    if (
        header_size < (64 if wide else 52)
        or count == 65535
        or (count and step < (56 if wide else 32))
    ):
        raise ValueError("ELF header size or extended program-header numbering is unsupported.")
    _bounds(data, 0, header_size)
    _bounds(data, table, step * count)
    regions = []
    for index in range(count):
        at = table + step * index
        if _number(data, at, "I", end) != 1:
            continue
        offset = _number(data, at + (8 if wide else 4), "Q" if wide else "I", end)
        address = _number(data, at + (16 if wide else 8), "Q" if wide else "I", end)
        size = _number(data, at + (32 if wide else 16), "Q" if wide else "I", end)
        memory_size = _number(data, at + (40 if wide else 20), "Q" if wide else "I", end)
        if size > memory_size or address + memory_size > 2**layout.bits:
            raise ValueError("ELF file size exceeds memory size or mapped address range overflows.")
        flags = _number(data, at + (4 if wide else 24), "I", end)
        regions.append(_region(data, f"LOAD {index}", offset, size, address, bool(flags & 1)))
    layout.regions = regions


def read_layout(data: bytes) -> Layout:
    layout = Layout()
    try:
        if data.startswith(b"MZ"):
            _pe(data, layout)
        elif data.startswith(b"\x7fELF"):
            _elf(data, layout)
        else:
            layout.notes.append(
                "Format/architecture unknown: only PE and ELF header mapping is implemented."
            )
    except ValueError as error:
        layout.regions.clear()
        layout.notes.append(str(error))
    return layout


def inspect_bytes(
    data: bytes, options: LowreaOptions, filename: str, task: TaskContext | None = None
) -> Evidence:
    task = task or TaskContext()
    digest = hashlib.sha256()
    for offset in range(0, len(data), 65536):
        task.check()
        digest.update(data[offset : offset + 65536])
    task.check()
    sha = digest.hexdigest()
    if options.expected_sha256 is not None and options.expected_sha256 != sha:
        raise ValueError("Artifact changed. Inspect the file again before continuing.")
    layout = read_layout(data)
    start = options.offset
    if start is None:
        start = layout.file_offset(layout.entry) if layout.entry is not None else None
    automatic_entry = start is not None and options.offset is None
    start = start if start is not None else 0
    if start > len(data):
        raise ValueError("File offset is beyond the artifact.")
    window = data[start : start + options.length]
    address = layout.file_address(start)
    space = "preferred-virtual" if address is not None else "declared-raw"
    address = address if address is not None else options.base_address + start
    if address + len(window) > 2**64:
        raise ValueError("Decode address range overflows 64 bits.")
    architecture = layout.architecture if options.architecture == "auto" else options.architecture
    endian = layout.endian if options.architecture == "auto" else options.endian
    notes = list(layout.notes) + [
        "Evidence identifies captured bytes; capture is not an atomic filesystem snapshot.",
        "Selected-window decoding is not function recovery, decompilation, "
        "or proof of reachability.",
        "References cover only RIP-relative operands in the selected x86-64 window; "
        "all other xrefs remain unknown.",
    ]
    if options.architecture != "auto":
        notes.append(
            "Decoder architecture was declared by the caller; it is not inferred from the artifact."
        )
    decoder_data = window
    mapped = [r for r in layout.regions if r.offset <= start < r.offset + r.size]
    if space == "preferred-virtual":
        decoder_data = window[: min(r.offset + r.size for r in mapped) - start]
        if len(decoder_data) < len(window):
            notes.append(
                "Decoding stops at the mapped range boundary; "
                "remaining hex bytes are unmapped here."
            )
    if automatic_entry:
        if len(mapped) != 1 or not mapped[0].executable:
            decoder_data = b""
            notes.append("Entry point is not unambiguously backed by an executable file range.")
        else:
            decoder_data = decoder_data[: mapped[0].offset + mapped[0].size - start]
    elif options.offset is None and options.architecture == "auto":
        decoder_data = b""
        notes.append("No mapped entry point: choose an architecture and/or explicit file offset.")
    instructions: list[JsonValue] = []
    references: list[JsonValue] = []
    version = "unavailable"
    decoded = 0
    if architecture not in {"x86", "x86-64", "arm64"}:
        notes.append("No supported decoder architecture is known.")
    elif decoder_data:
        try:
            cap: Any = importlib.import_module("capstone")
            version = str(cap.__version__)
            arch, mode = {
                "x86": (cap.CS_ARCH_X86, cap.CS_MODE_32),
                "x86-64": (cap.CS_ARCH_X86, cap.CS_MODE_64),
                "arm64": (cap.CS_ARCH_ARM64, cap.CS_MODE_ARM),
            }[architecture]
            engine = cap.Cs(arch, mode | (cap.CS_MODE_BIG_ENDIAN if endian == "big" else 0))
            engine.detail = True
            x86 = (
                importlib.import_module("capstone.x86_const") if architecture == "x86-64" else None
            )
            for instruction in engine.disasm(decoder_data, address):
                task.check()
                at, size = int(instruction.address), int(instruction.size)
                instructions.append(
                    {
                        "address": f"0x{at:016x}",
                        "address_space": space,
                        "file_offset": start + at - address,
                        "bytes": bytes(instruction.bytes).hex(),
                        "mnemonic": str(instruction.mnemonic),
                        "operands": str(instruction.op_str),
                    }
                )
                decoded += size
                if x86 is not None:
                    for operand in instruction.operands:
                        if operand.type == x86.X86_OP_MEM and operand.mem.base == x86.X86_REG_RIP:
                            target = (at + size + int(operand.mem.disp)) % (2**64)
                            segment_unknown = (
                                operand.mem.segment in {x86.X86_REG_FS, x86.X86_REG_GS}
                                and instruction.mnemonic != "lea"
                            )
                            physical = (
                                layout.file_offset(target)
                                if space == "preferred-virtual" and not segment_unknown
                                else None
                            )
                            reference_bytes = b""
                            if physical is not None:
                                end = min(
                                    r.offset + r.size
                                    for r in layout.regions
                                    if r.offset <= physical < r.offset + r.size
                                )
                                reference_bytes = data[physical : min(end, physical + 256)]
                            match = (
                                re.match(rb"[ -~]{4,}", reference_bytes)
                                if physical is not None
                                else None
                            )
                            references.append(
                                {
                                    "instruction_address": f"0x{at:016x}",
                                    "target_address": f"0x{target:016x}",
                                    "file_offset": physical,
                                    "segment_base_unknown": segment_unknown,
                                    "string_prefix_only": bool(
                                        match and match.end() == len(reference_bytes)
                                    ),
                                    "possible_string": (
                                        match.group().decode("ascii") if match else None
                                    ),
                                    "confidence": "derived",
                                }
                            )
        except (ImportError, OSError):
            notes.append("Capstone native component unavailable; reinstall the locked environment.")
        except Exception as error:
            # A native decoder failure does not discard already-produced identity/header facts.
            if error.__class__.__module__.startswith("capstone"):
                notes.append("Capstone could not decode this architecture/mode.")
            else:
                raise
    if decoded < len(decoder_data):
        notes.append(
            "Decoding stopped before the window ended; "
            "remaining bytes are undecoded, not absent code."
        )
    strings: list[JsonValue] = [
        {"file_offset": start + m.start(), "value": m.group().decode("ascii")}
        for m in re.finditer(rb"[ -~]{4,}", window)
    ]
    profile = options.model_dump(mode="json", exclude={"workspace_id", "expected_sha256"})
    facts: dict[str, JsonValue] = {
        "filename": filename,
        "size": len(data),
        "headers": {
            "format": layout.format,
            "architecture": layout.architecture,
            "bits": layout.bits,
            "endian": layout.endian,
            "entrypoint": f"0x{layout.entry:016x}" if layout.entry is not None else None,
        },
        "regions": [
            {
                "name": r.name,
                "file_offset": r.offset,
                "size": r.size,
                "preferred_address": f"0x{r.address:016x}",
                "executable": r.executable,
            }
            for r in layout.regions
        ],
        "window": {
            "offset": start,
            "length": len(window),
            "requested_length": options.length,
            "hex": window.hex(),
        },
        "decoder": {"architecture": architecture, "version": version, "bytes_decoded": decoded},
        "instructions": instructions,
        "references": references,
        "strings": strings,
        "unknowns": [note for note in notes],
    }
    task.check()
    return Evidence.create(
        "inspect_static",
        facts,
        subject_sha256=sha,
        provider_id="builtin-static+capstone" if version != "unavailable" else "builtin-static",
        provider_version="1/" + version if version != "unavailable" else "1",
        confidence="derived",
        parameters={
            "profile": profile,
            "profile_sha256": hashlib.sha256(
                json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        },
        limitations=tuple(notes),
    )
