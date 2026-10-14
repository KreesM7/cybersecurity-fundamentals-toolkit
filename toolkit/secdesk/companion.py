"""USB-serial metadata and a firmware adapter boundary. No guessed wire commands."""

from __future__ import annotations

import importlib
from typing import Any, Protocol

from pydantic import Field

from toolkit.secdesk.registry import Contract


class SerialPort(Contract):
    device: str
    description: str
    vendor_id: int | None = Field(default=None, ge=0, le=65535)
    product_id: int | None = Field(default=None, ge=0, le=65535)


class FirmwareAdapter(Protocol):
    """A future adapter must implement the device owner's actual firmware spec."""

    vendor_id: int
    product_id: int
    baud_rate: int
    capabilities: frozenset[str]

    def encode(self, operation: str, payload: bytes) -> bytes: ...

    def decode(self, payload: bytes) -> bytes: ...


def ports() -> list[SerialPort]:
    module = importlib.import_module("serial.tools.list_ports")
    return [
        SerialPort(
            device=port.device,
            description=port.description,
            vendor_id=port.vid,
            product_id=port.pid,
        )
        for port in list(module.comports())[:256]
    ]


class CompanionTransport:
    def __init__(self, adapter: FirmwareAdapter | None = None) -> None:
        self.adapter = adapter
        self._serial: Any = None

    def connect(self, device: str) -> None:
        if self.adapter is None:
            raise ValueError("Firmware protocol and USB IDs required; device actions disabled")
        if self._serial is not None:
            raise ValueError("Close the owned device connection first")
        match = next((port for port in ports() if port.device == device), None)
        if match is None or (match.vendor_id, match.product_id) != (
            self.adapter.vendor_id,
            self.adapter.product_id,
        ):
            raise ValueError("Selected USB device does not match the firmware adapter")
        if not 1 <= self.adapter.baud_rate <= 4000000:
            raise ValueError("Unsupported firmware baud rate")
        module = importlib.import_module("serial")
        self._serial = module.Serial(device, self.adapter.baud_rate, timeout=1, write_timeout=1)

    def exchange(self, operation: str, payload: bytes, *, authorized: bool = False) -> bytes:
        # Retain the legacy argument for callers; operation support comes from the firmware.
        if self.adapter is None or self._serial is None:
            raise ValueError("No protocol-backed device connection")
        if operation not in self.adapter.capabilities:
            raise ValueError("A firmware-supported operation is required")
        if len(payload) > 65536:
            raise ValueError("Device payload exceeds limit")
        command = self.adapter.encode(operation, payload)
        if not command or len(command) > 65536:
            raise ValueError("Firmware command exceeds limit")
        written = self._serial.write(command)
        if written != len(command):
            raise ValueError("Incomplete device write; outcome unknown and not repeated")
        return self.adapter.decode(self._serial.read(65536))

    def close(self) -> None:
        if self._serial is not None:
            self._serial.close()
            self._serial = None
