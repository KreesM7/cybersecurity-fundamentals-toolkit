from collections import Counter
from dataclasses import dataclass
import math

from toolkit.core import ModuleSpec
from toolkit.tasks import TaskContext


@dataclass(frozen=True)
class Spike:
    source_ip: str
    bin_start: int
    count: int


def detect_spikes(events, threshold=100, task=None):
    if type(threshold) is not int or threshold < 1:
        raise ValueError('Threshold must be a positive integer.')
    task = task or TaskContext()
    counts = Counter()
    for index, event in enumerate(events):
        if index % 1000 == 0:
            task.check()
        counts[(event.source_ip, math.floor(event.timestamp))] += 1
    return [Spike(source, second, count) for (source, second), count in sorted(
        counts.items(), key=lambda item: (item[0][1], item[0][0])) if count > threshold]


def create_panel(context):
    from PySide6.QtWidgets import QHBoxLayout, QLabel, QSpinBox
    from toolkit.traffic import input_summary, read_traffic, utc_label
    from toolkit.widgets import FileInput, TaskPanel, fill_table, make_table

    panel = TaskPanel(context, 'DoS Pattern Detector',
                      'Inspect saved access logs, request CSV, or PCAP files. Counts strictly above the '
                      'threshold in a UTC-aligned one-second bin are flagged. A spike alone does not establish an attack.')
    source = FileInput('Traffic files (*.log *.txt *.csv *.pcap *.pcapng);;All files (*)')
    panel.layout.addWidget(source)
    controls = QHBoxLayout()
    controls.addWidget(QLabel('Threshold per IP / second'))
    threshold = QSpinBox()
    threshold.setRange(1, 1000000)
    threshold.setValue(100)
    controls.addWidget(threshold)
    controls.addStretch()
    panel.layout.addLayout(controls)
    results = make_table(['Bin start (UTC)', 'Source IP', 'Count', 'Unit'])
    panel.layout.addWidget(results, 1)
    panel.add_footer()

    def run():
        filename, limit = source.path.text(), threshold.value()
        fill_table(results, [])

        def work(task):
            data = read_traffic(filename, task=task)
            return data, detect_spikes(data.events, limit, task)

        def done(result):
            data, spikes = result
            fill_table(results, ((utc_label(s.bin_start), s.source_ip, s.count, data.unit) for s in spikes))
            panel.status.setText(input_summary(data) + f'\n{len(spikes):,} spikes above {limit}; showing at most 5,000.')

        panel.start(work, done)

    panel.run_button.clicked.connect(run)
    return panel


MODULE = ModuleSpec('dos-detector', 'DoS Pattern Detector', 40, create_panel)
