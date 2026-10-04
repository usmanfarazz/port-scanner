"""Unit tests for port_scanner.py. Run with: python3 -m unittest discover -s tests -v"""
import csv
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import port_scanner as ps  # noqa: E402


class ParsePortsTest(unittest.TestCase):
    def test_single_list_and_range(self):
        self.assertEqual(ps.parse_ports("22,80,1000-1002"), [22, 80, 1000, 1001, 1002])

    def test_duplicates_removed_and_sorted(self):
        self.assertEqual(ps.parse_ports("443,22,22,80"), [22, 80, 443])

    def test_reversed_range_is_accepted(self):
        self.assertEqual(ps.parse_ports("82-80"), [80, 81, 82])

    def test_invalid_spec_gives_clear_error(self):
        with self.assertRaisesRegex(ValueError, "invalid port or range: 'abc'"):
            ps.parse_ports("22,abc")

    def test_out_of_range_ports_dropped(self):
        self.assertEqual(ps.parse_ports("0,1,65535,65536"), [1, 65535])


class ScanPortTest(unittest.TestCase):
    def setUp(self):
        # A tiny local server that sends a banner, so the test needs no network.
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.port = self.server.getsockname()[1]

        def serve():
            try:
                conn, _ = self.server.accept()
                conn.sendall(b"TEST-SERVICE 1.0\r\n")
                conn.close()
            except OSError:
                pass

        threading.Thread(target=serve, daemon=True).start()

    def tearDown(self):
        self.server.close()

    def test_open_port_with_banner(self):
        result = ps.scan_port("127.0.0.1", self.port, 1.0)
        self.assertEqual(result["port"], self.port)
        self.assertEqual(result["banner"], "TEST-SERVICE 1.0")

    def test_closed_port_returns_none(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        self.assertIsNone(ps.scan_port("127.0.0.1", port, 0.5))


class SaveResultsTest(unittest.TestCase):
    RESULTS = [{"port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH"}]

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            ps.save_results(path, "localhost", "127.0.0.1", 100, datetime(2026, 1, 1), self.RESULTS)
            with open(path) as fh:
                data = json.load(fh)
        self.assertEqual(data["ports_scanned"], 100)
        self.assertEqual(data["open_ports"], self.RESULTS)

    def test_csv_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.csv")
            ps.save_results(path, "localhost", "127.0.0.1", 100, datetime(2026, 1, 1), self.RESULTS)
            with open(path, newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertEqual(rows[0]["port"], "22")
        self.assertEqual(rows[0]["service"], "SSH")

    def test_bad_extension_rejected(self):
        with self.assertRaises(ValueError):
            ps.save_results("r.txt", "h", "1.1.1.1", 1, datetime.now(), [])


if __name__ == "__main__":
    unittest.main()
