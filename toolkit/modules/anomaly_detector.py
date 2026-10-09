from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QWidget

    from frontend.viewmodels.tools_vm import ToolsViewModel

import math
import statistics
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

from toolkit.core import ModuleSpec
from toolkit.task_context import TaskContext
from toolkit.traffic import TrafficEvent


@dataclass(frozen=True)
class Anomaly:
    bin_start: float
    metric: str
    value: float
    baseline: float
    zscore: float


@dataclass
class AnomalyReport:
    anomalies: list[Anomaly]
    sufficient: bool
    examined: int
    total: int = 0


def _score(value: float, history: Iterable[float]) -> tuple[float, float]:
    mean = statistics.fmean(history)
    deviation = statistics.pstdev(history)
    if deviation == 0:
        # A different value against an unchanging baseline cannot have a finite z-score.
        return mean, 0.0 if value == mean else math.copysign(math.inf, value - mean)
    return mean, (value - mean) / deviation


def detect_anomalies(
    events: list[TrafficEvent],
    bin_seconds: int = 1,
    baseline_bins: int = 30,
    threshold: float = 3,
    task: TaskContext | None = None,
) -> AnomalyReport:
    if type(bin_seconds) is not int or not 1 <= bin_seconds <= 3600:
        raise ValueError("Bin size must be an integer from 1 to 3600 seconds.")
    if type(baseline_bins) is not int or not 2 <= baseline_bins <= 120:
        raise ValueError("Baseline must contain 2 to 120 bins.")
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError("Z-score threshold must be positive and finite.")
    task = task or TaskContext()
    if not events:
        return AnomalyReport([], False, 0)
    bins: dict[int, tuple[int, Counter[str]]] = {}
    protocol_names: set[str] = set()
    for index, event in enumerate(events):
        if index % 1000 == 0:
            task.check()
        bucket = math.floor(event.timestamp / bin_seconds)
        protocol_names.add(event.protocol)
        if len(protocol_names) > 64:
            raise ValueError(
                "More than 64 protocol labels. Group uncommon protocols before analysis."
            )
        size, protocols = bins.setdefault(bucket, (0, Counter()))
        bins[bucket] = (size + event.bytes, protocols)
        protocols[event.protocol] += 1
    first, last = min(bins), max(bins)
    if last - first + 1 > 100000:
        raise ValueError("Time span exceeds 100,000 bins. Increase bin size or split the file.")
    history: deque[tuple[int, int, dict[str, float]]] = deque(maxlen=baseline_bins)
    findings: list[Anomaly] = []
    examined, total_findings = 0, 0
    for bucket in range(first, last + 1):
        task.check()
        size, counts = bins.get(bucket, (0, Counter()))
        total = sum(counts.values())
        proportions = (
            {protocol: count / total for protocol, count in counts.items()} if total else {}
        )
        if len(history) == baseline_bins:
            examined += 1
            observed_protocols = set(proportions).union(*(item[2] for item in history))

            def metrics() -> Iterator[tuple[str, float, list[float]]]:
                yield "Bytes", size, [item[0] for item in history]
                yield "Events", total, [item[1] for item in history]
                for protocol in sorted(observed_protocols):
                    task.check()
                    yield "Protocol " + protocol, proportions.get(protocol, 0), [
                        item[2].get(protocol, 0) for item in history
                    ]

            for metric, value, previous in metrics():
                task.check()
                mean, zscore = _score(value, previous)
                if abs(zscore) > threshold:
                    total_findings += 1
                    if len(findings) < 5000:
                        findings.append(Anomaly(bucket * bin_seconds, metric, value, mean, zscore))
        history.append((size, total, proportions))
    return AnomalyReport(findings, examined > 0, examined, total_findings)


def readiness() -> str:
    return "CSV/log ready; saved captures require the separate PCAP worker."


def create_panel(context: ToolsViewModel) -> QWidget:
    from frontend.views.tools import create_panel as factory

    return factory(MODULE.id, context)


MODULE = ModuleSpec("anomaly-detector", "Network Anomaly Detector", 60, create_panel)
