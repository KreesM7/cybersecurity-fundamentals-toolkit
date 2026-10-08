"""Isolated pure backend extension discovery."""

import pkgutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from importlib import import_module
from typing import Protocol

from backend.jobs import JobContext
from shared.tools import ToolOptions, ToolView


class ToolRuntime(Protocol):
    async def analyze(
        self,
        tool_id: str,
        options: ToolOptions,
        content: bytes | None,
        filename: str,
        context: JobContext,
    ) -> object: ...


@dataclass(frozen=True)
class ToolSpec:
    id: str
    title: str
    order: int
    run: Callable[[ToolRuntime, ToolOptions, bytes | None, str, JobContext], Awaitable[object]]
    readiness: Callable[[], str] = lambda: ""
    note: str = ""


def discover_tools() -> tuple[dict[str, ToolSpec], list[ToolView]]:
    specs: dict[str, ToolSpec] = {}
    failed: list[ToolView] = []
    for entry in pkgutil.iter_modules(__path__):
        if entry.name.startswith("_"):
            continue
        try:
            spec = import_module(f"backend.tools.{entry.name}").TOOL
            if not isinstance(spec, ToolSpec) or spec.id in specs:
                raise ValueError("Invalid or duplicate tool registration")
            specs[spec.id] = spec
        except Exception:
            failed.append(
                ToolView(
                    id=entry.name.replace("_", "-"),
                    title=entry.name,
                    order=1000,
                    available=False,
                    reason="Tool registration unavailable; reinstall this extension.",
                )
            )
    return specs, failed
