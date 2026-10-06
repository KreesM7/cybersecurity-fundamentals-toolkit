from collections import Counter, deque
from dataclasses import dataclass
import math
import statistics

from toolkit.core import ModuleSpec
from toolkit.tasks import TaskContext


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


def _score(value, history):
    mean = statistics.fmean(history)
    deviation = statistics.pstdev(history)
    if deviation == 0:
        # A different value against an unchanging baseline cannot have a finite z-score.
        return mean, 0.0 if value == mean else math.copysign(math.inf, value - mean)
    return mean, (value - mean) / deviation


def detect_anomalies(events, bin_seconds=1, baseline_bins=30, threshold=3, task=None):
    if type(bin_seconds) is not int or not 1 <= bin_seconds <= 3600:
        raise ValueError('Bin size must be an integer from 1 to 3600 seconds.')
    if type(baseline_bins) is not int or not 2 <= baseline_bins <= 120:
        raise ValueError('Baseline must contain 2 to 120 bins.')
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError('Z-score threshold must be positive and finite.')
    task = task or TaskContext()
    if not events:
        return AnomalyReport([], False, 0)
    bins = {}
    for index, event in enumerate(events):
        if index % 1000 == 0:
            task.check()
        bucket = math.floor(event.timestamp / bin_seconds)
        size, protocols = bins.setdefault(bucket, [0, Counter()])
        bins[bucket][0] = size + event.bytes
        protocols[event.protocol] += 1
    first, last = min(bins), max(bins)
    if last - first + 1 > 100000:
        raise ValueError('Time span exceeds 100,000 bins. Increase bin size or split the file.')
    history = deque(maxlen=baseline_bins)
    findings, examined = [], 0
    for bucket in range(first, last + 1):
        task.check()
        size, counts = bins.get(bucket, (0, Counter()))
        total = sum(counts.values())
        proportions = {protocol: count / total for protocol, count in counts.items()} if total else {}
        if len(history) == baseline_bins:
            examined += 1
            metrics = {'Bytes': (size, [item[0] for item in history]),
                       'Events': (total, [item[1] for item in history])}
            protocols = set(proportions).union(*(item[2] for item in history))
            for protocol in sorted(protocols):
                metrics['Protocol ' + protocol] = (proportions.get(protocol, 0),
                                                   [item[2].get(protocol, 0) for item in history])
            for metric, (value, previous) in metrics.items():
                mean, zscore = _score(value, previous)
                if abs(zscore) > threshold:
                    findings.append(Anomaly(bucket * bin_seconds, metric, value, mean, zscore))
        history.append((size, total, proportions))
    return AnomalyReport(findings, examined > 0, examined)


def readiness():
    try:
        import scapy
    except ImportError:
        return 'CSV/log ready; install Scapy for saved PCAP files.'
    return ''


def create_panel(context):
    from PySide6.QtWidgets import QDoubleSpinBox, QHBoxLayout, QLabel, QSpinBox
    from toolkit.traffic import input_summary, read_traffic, utc_label
    from toolkit.widgets import FileInput, TaskPanel, fill_table, make_table

    panel = TaskPanel(context, 'Network Anomaly Detector',
                      'Compare byte volume, event counts, and protocol proportions with preceding bins. '
                      'Empty bins count as zero. Zero variance with a changed value is shown as infinite z. '
                      'Anomalies are clues for investigation, not proof of malicious activity.')
    source = FileInput('Traffic files (*.log *.txt *.csv *.pcap *.pcapng);;All files (*)')
    panel.layout.addWidget(source)
    controls = QHBoxLayout()
    interval, baseline, threshold = QSpinBox(), QSpinBox(), QDoubleSpinBox()
    interval.setRange(1, 3600)
    interval.setValue(1)
    baseline.setRange(2, 120)
    baseline.setValue(30)
    threshold.setRange(0.1, 20)
    threshold.setValue(3)
    for label, control in [('Bin seconds', interval), ('Baseline bins', baseline), ('Z threshold', threshold)]:
        controls.addWidget(QLabel(label))
        controls.addWidget(control)
    controls.addStretch()
    panel.layout.addLayout(controls)
    results = make_table(['Bin start (UTC)', 'Metric', 'Value', 'Baseline mean', 'Z-score'])
    panel.layout.addWidget(results, 1)
    panel.add_footer()

    def run():
        filename = source.path.text()
        options = interval.value(), baseline.value(), threshold.value()
        fill_table(results, [])

        def work(task):
            data = read_traffic(filename, require_volume=True, task=task)
            return data, detect_anomalies(data.events, *options, task=task)

        def done(result):
            data, report = result
            fill_table(results, ((utc_label(a.bin_start), a.metric, f'{a.value:.4g}', f'{a.baseline:.4g}',
                                  f'{a.zscore:.3g}') for a in report.anomalies))
            state = f'{len(report.anomalies):,} anomalies in {report.examined:,} evaluated bins; showing at most 5,000.'
            if not report.sufficient:
                state = f'Insufficient baseline data: need at least {options[1] + 1} bins.'
            panel.status.setText(input_summary(data) + '\n' + state)

        panel.start(work, done)

    panel.run_button.clicked.connect(run)
    return panel


MODULE = ModuleSpec('anomaly-detector', 'Network Anomaly Detector', 60, create_panel)
