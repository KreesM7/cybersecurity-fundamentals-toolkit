import importlib
import tempfile
import unittest
from pathlib import Path


class TrafficTests(unittest.TestCase):
    def reader(self):
        try:
            return importlib.import_module('toolkit.traffic')
        except ModuleNotFoundError:
            self.fail('The saved traffic reader has not been implemented.')

    def test_csv_sorts_timestamps_and_reports_bad_rows(self):
        reader = self.reader()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'traffic.csv'
            path.write_text('timestamp,source_ip,bytes,protocol\n'
                            '2026-10-06T00:00:02Z,10.0.0.1,20,TCP\n'
                            'bad,10.0.0.1,40,TCP\n'
                            '2026-10-06T00:00:01+00:00,10.0.0.2,10,UDP\n')
            data = reader.read_traffic(path, require_volume=True)
            self.assertEqual([event.bytes for event in data.events], [10, 20])
            self.assertFalse(data.complete)
            self.assertEqual(data.skipped, 1)
            self.assertTrue(data.warnings)

    def test_access_log_and_timezone_free_timestamp(self):
        reader = self.reader()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'access.log'
            path.write_text('10.0.0.8 - - [06/Oct/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 42\n')
            event = reader.read_traffic(path, require_volume=True).events[0]
            self.assertEqual((event.source_ip, event.bytes, event.protocol), ('10.0.0.8', 42, 'HTTP'))
        with self.assertRaises(ValueError):
            reader.parse_timestamp('2026-10-06T00:00:01')
        with self.assertRaises(ValueError):
            reader.parse_timestamp('nan')

    def test_pcap_uses_packets_and_rejects_invalid_capture(self):
        reader = self.reader()
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, TCP
        from scapy.utils import wrpcap
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'sample.pcap'
            packet = Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')/IP(src='10.0.0.2', dst='10.0.0.3')/TCP(dport=80)
            packet.time = 1000.25
            wrpcap(str(path), [packet])
            data = reader.read_traffic(path)
            self.assertEqual(data.unit, 'packets')
            self.assertEqual(data.events[0].protocol, 'TCP')
            self.assertEqual(data.events[0].timestamp, 1000.25)
            original = path.read_bytes()
            path.write_bytes(original[:-4])
            with self.assertRaises(ValueError):
                reader.read_traffic(path)
            path.write_bytes(b'not a capture')
            with self.assertRaises(ValueError):
                reader.read_traffic(path)

    def test_dos_threshold_is_strict_and_groups_by_source(self):
        reader = self.reader()
        try:
            module = importlib.import_module('toolkit.modules.dos_detector')
        except ModuleNotFoundError:
            self.fail('The DoS detector has not been implemented.')
        events = [reader.TrafficEvent(2.1, '10.0.0.1', 1, 'TCP') for _ in range(101)]
        events += [reader.TrafficEvent(1.1, '10.0.0.2', 1, 'TCP') for _ in range(100)]
        result = module.detect_spikes(events, threshold=100)
        self.assertEqual([(r.source_ip, r.count) for r in result], [('10.0.0.1', 101)])

    def test_anomalies_compare_with_preceding_baseline(self):
        reader = self.reader()
        try:
            module = importlib.import_module('toolkit.modules.anomaly_detector')
        except ModuleNotFoundError:
            self.fail('The anomaly detector has not been implemented.')
        events = [reader.TrafficEvent(i + 0.1, '10.0.0.1', 10, 'TCP') for i in range(30)]
        events += [reader.TrafficEvent(30.1, '10.0.0.1', 1000, 'UDP') for _ in range(10)]
        report = module.detect_anomalies(events)
        self.assertTrue(any(a.metric == 'Bytes' and a.bin_start == 30 for a in report.anomalies))
        self.assertTrue(any(a.metric == 'Protocol UDP' for a in report.anomalies))
        self.assertFalse(module.detect_anomalies(events[:5]).sufficient)


if __name__ == '__main__':
    unittest.main()
