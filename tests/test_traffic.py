import importlib
import tempfile
import unittest
from pathlib import Path


class TrafficTests(unittest.TestCase):
    def reader(self):
        try:
            return importlib.import_module("toolkit.traffic")
        except ModuleNotFoundError:
            self.fail("The saved traffic reader has not been implemented.")

    def test_csv_sorts_timestamps_and_reports_bad_rows(self):
        reader = self.reader()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "traffic.csv"
            path.write_text(
                "timestamp,source_ip,bytes,protocol\n"
                "2026-10-06T00:00:02Z,10.0.0.1,20,TCP\n"
                "bad,10.0.0.1,40,TCP\n"
                "2026-10-06T00:00:01+00:00,10.0.0.2,10,UDP\n"
            )
            data = reader.read_traffic(path, require_volume=True)
            self.assertEqual([event.bytes for event in data.events], [10, 20])
            self.assertFalse(data.complete)
            self.assertEqual(data.skipped, 1)
            self.assertTrue(data.warnings)

    def test_access_log_and_timezone_free_timestamp(self):
        reader = self.reader()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "access.log"
            path.write_text(
                '10.0.0.8 - - [06/Oct/2026:00:00:02 +0000] "GET / HTTP/1.1" 200 99\n'
                '10.0.0.8 - - [06/Oct/2026:00:00:01 +0000] "GET / HTTP/1.1" 200 42\n'
            )
            events = reader.read_traffic(path, require_volume=True).events
            event = events[0]
            self.assertEqual(
                (event.source_ip, event.bytes, event.protocol), ("10.0.0.8", 42, "HTTP")
            )
            self.assertEqual([event.bytes for event in events], [42, 99])
        with self.assertRaises(ValueError):
            reader.parse_timestamp("2026-10-06T00:00:01")
        with self.assertRaises(ValueError):
            reader.parse_timestamp("nan")

    def test_pcap_is_actionably_unavailable_without_scapy_in_desktop(self):
        # Capture decoding moves to Slice5's external worker; retain framing,
        # truncation and cancellation fixtures in that worker's regression suite.
        import sys

        reader = self.reader()
        before = set(sys.modules)
        for suffix in (".pcap", ".pcapng"):
            with self.assertRaisesRegex(ValueError, "separate PCAP worker"):
                reader.read_traffic_bytes(b"capture fixture", "sample" + suffix)
        self.assertFalse(
            any(name == "scapy" or name.startswith("scapy.") for name in set(sys.modules) - before)
        )
        for module in ("dos_detector", "anomaly_detector"):
            status = importlib.import_module("toolkit.modules." + module).readiness()
            self.assertIn("CSV/log ready", status)
            self.assertIn("separate PCAP worker", status)

    def test_dos_threshold_is_strict_and_groups_by_source(self):
        reader = self.reader()
        try:
            module = importlib.import_module("toolkit.modules.dos_detector")
        except ModuleNotFoundError:
            self.fail("The DoS detector has not been implemented.")
        events = [reader.TrafficEvent(2.1, "10.0.0.1", 1, "TCP") for _ in range(101)]
        events += [reader.TrafficEvent(1.1, "10.0.0.2", 1, "TCP") for _ in range(100)]
        result = module.detect_spikes(events, threshold=100)
        self.assertEqual([(r.source_ip, r.count) for r in result], [("10.0.0.1", 101)])

    def test_anomalies_compare_with_preceding_baseline(self):
        reader = self.reader()
        try:
            module = importlib.import_module("toolkit.modules.anomaly_detector")
        except ModuleNotFoundError:
            self.fail("The anomaly detector has not been implemented.")
        events = [reader.TrafficEvent(i + 0.1, "10.0.0.1", 10, "TCP") for i in range(30)]
        events += [reader.TrafficEvent(30.1, "10.0.0.1", 1000, "UDP") for _ in range(10)]
        report = module.detect_anomalies(events)
        self.assertTrue(any(a.metric == "Bytes" and a.bin_start == 30 for a in report.anomalies))
        self.assertTrue(any(a.metric == "Protocol UDP" for a in report.anomalies))
        self.assertFalse(module.detect_anomalies(events[:5]).sufficient)

    def test_protocol_cardinality_and_result_storage_are_bounded(self):
        reader = self.reader()
        module = importlib.import_module("toolkit.modules.anomaly_detector")
        events = [reader.TrafficEvent(i % 3, "10.0.0.1", 1, f"P{i}") for i in range(1000)]
        with self.assertRaisesRegex(ValueError, "protocol"):
            module.detect_anomalies(events, baseline_bins=2)
        # Alternating volume triggers enough anomalies to exceed the display limit.
        events = [reader.TrafficEvent(i, "10.0.0.1", i % 2, "TCP") for i in range(5200)]
        report = module.detect_anomalies(events, baseline_bins=2, threshold=0.1)
        self.assertGreater(report.total, 5000)
        self.assertEqual(len(report.anomalies), 5000)


if __name__ == "__main__":
    unittest.main()
