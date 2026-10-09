from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from frontend.viewmodels.tools_vm import ToolsViewModel

import math
from collections import Counter
from dataclasses import dataclass

from toolkit.core import ModuleSpec
from toolkit.task_context import TaskContext
from toolkit.traffic import TrafficEvent


@dataclass(frozen=True)
class Spike:
    source_ip: str
    bin_start: int
    count: int


def detect_spikes(
    events: list[TrafficEvent], threshold: int = 100, task: TaskContext | None = None
) -> list[Spike]:
    if type(threshold) is not int or threshold < 1:
        raise ValueError("Threshold must be a positive integer.")
    task = task or TaskContext()
    counts: Counter[tuple[str, int]] = Counter()
    for index, event in enumerate(events):
        if index % 1000 == 0:
            task.check()
        counts[(event.source_ip, math.floor(event.timestamp))] += 1
    return [
        Spike(source, second, count)
        for (source, second), count in sorted(
            counts.items(), key=lambda item: (item[0][1], item[0][0])
        )
        if count > threshold
    ]


def readiness() -> str:
    return "CSV/log ready; saved captures require the separate PCAP worker."


def create_panel(context: ToolsViewModel) -> QWidget:
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("dos-detector", "DoS Pattern Detector", 40, create_panel)
