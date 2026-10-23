"""Read-only serial discovery checks; no physical serial port is accessed."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gui"))

from diagnostics import serial_discovery as discovery


class FakeClient:
    def __init__(self, replies, connected=True, on_read=None):
        self.replies = iter(replies)
        self.connected = connected
        self.on_read = on_read
        self.last_error = None
        self.last_error_category = None
        self.last_exception_code = None
        self.last_tx_bytes = b""
        self.last_rx_bytes = b""
        self.calls = []
        self.closed = 0

    def connect(self):
        return self.connected

    def disconnect(self):
        self.closed += 1

    def _read(self, function, address, count):
        self.calls.append((function, address, count))
        reply = next(self.replies)
        if isinstance(reply, Exception):
            raise reply
        self.last_error_category = reply.get("category")
        self.last_exception_code = reply.get("exception")
        self.last_error = reply.get("error")
        self.last_tx_bytes = reply.get("tx", b"\x01\x03\x00\x00\x00\x01")
        self.last_rx_bytes = reply.get("rx", b"\x01\x03\x02\x00\x2a")
        if self.on_read:
            self.on_read()
        return reply.get("result")

    def read_registers(self, address, count):
        return self._read(3, address, count)

    def read_input_registers(self, address, count):
        return self._read(4, address, count)


class SerialDiscoveryTests(unittest.TestCase):
    def worker(self, **options):
        worker = discovery.SerialParamScanWorker("COM8", "rtu", 1, 1, 0.2,
                                                 baud_rates=[9600], **options)
        worker._probe_pause = lambda _baud: None
        self.evidence, self.matches, self.completed, self.output = [], [], [], []
        worker.combo_evidence.connect(self.evidence.append)
        worker.combo_matched.connect(lambda *args: self.matches.append(args))
        worker.scan_complete.connect(self.completed.append)
        worker.output.connect(self.output.append)
        return worker

    def run_worker(self, worker, client):
        with patch.object(discovery, "ModbusClient", return_value=client) as factory, \
                patch.object(discovery, "PARITIES_TO_TRY", ["N"]), \
                patch.object(discovery, "STOPBITS_TO_TRY", [1]):
            worker.run()
        self.assertEqual(client.closed, 1)
        self.assertEqual(factory.call_args.kwargs["retries"], 0)

    def test_repeated_data_accepts_zero_and_changing_values_with_actual_evidence(self):
        worker = self.worker(probe_address=65535)
        client = FakeClient([{"result": [0]}, {"result": [65535], "rx": b"\x01\x03\xff\xff"}])
        self.run_worker(worker, client)
        self.assertEqual(self.completed, [1])
        self.assertEqual(self.matches, [(9600, "N", 1, 1)])
        evidence = self.evidence[0]
        self.assertEqual(evidence["registers"], [65535])
        self.assertEqual(evidence["rx_hex"], "01 03 FF FF")
        self.assertEqual(evidence["data_replies"], 2)
        self.assertIn("Readable data", evidence["summary"])
        self.assertEqual(client.calls, [(3, 65535, 1), (3, 65535, 1)])

    def test_exceptions_confirm_communication_but_not_readable_data(self):
        worker = self.worker(probe_function="input", probe_address=100)
        client = FakeClient([{"category": "device_exception", "exception": 2}] * 2)
        self.run_worker(worker, client)
        self.assertEqual(self.completed, [1])
        self.assertEqual(self.evidence[0]["data_replies"], 0)
        self.assertEqual(self.evidence[0]["exception_codes"], [2, 2])
        self.assertNotIn("Readable", self.evidence[0]["summary"])
        self.assertEqual(client.calls, [(4, 100, 1), (4, 100, 1)])

    def test_single_valid_reply_then_timeout_is_unconfirmed(self):
        worker = self.worker()
        client = FakeClient([{"result": [42]}, {"category": "timeout", "error": "no reply"}])
        self.run_worker(worker, client)
        self.assertEqual(self.completed, [0])
        self.assertEqual(self.evidence, [])
        self.assertTrue(any("Unconfirmed reply" in line for line in self.output))

    def test_raw_garbage_wrong_count_and_stale_exception_are_not_matches(self):
        for reply in ({"rx": b"garbage", "category": "timeout"},
                      {"result": []}, {"result": [1, 2]}, {"result": [65536]},
                      {"result": [True]}, {"exception": 2, "category": "timeout"}):
            with self.subTest(reply=reply):
                worker = self.worker()
                client = FakeClient([reply])
                self.run_worker(worker, client)
                self.assertEqual(self.completed, [0])
                self.assertEqual(len(client.calls), 1)

    def test_read_failure_and_open_failure_cleanup_and_complete(self):
        for client in (FakeClient([RuntimeError("read failed")]), FakeClient([], connected=False)):
            with self.subTest(client=client):
                worker = self.worker()
                self.run_worker(worker, client)
                self.assertEqual(self.completed, [0])
                self.assertEqual(self.output[-1], "Scan aborted.")

    def test_cancellation_stops_confirmation_without_reporting_match(self):
        worker = self.worker()
        client = FakeClient([{"result": [42]}], on_read=worker.stop)
        self.run_worker(worker, client)
        self.assertEqual(self.completed, [0])
        self.assertEqual(self.matches, [])
        self.assertEqual(self.output[-1], "Scan stopped.")

    def test_second_dialog_cannot_scan_the_same_port_concurrently(self):
        worker = self.worker()
        competing = discovery.SerialParamScanWorker("com8", "rtu", 1, 1, 0.2, baud_rates=[9600])
        other_output, other_completed = [], []
        competing.output.connect(other_output.append)
        competing.scan_complete.connect(other_completed.append)
        client = FakeClient([{"result": [42]}] * 2, on_read=competing.run)
        self.run_worker(worker, client)
        self.assertEqual(self.completed, [1])
        self.assertEqual(other_completed, [0, 0])
        self.assertTrue(all("already running" in line for line in other_output))
        self.assertEqual(discovery._ACTIVE_SCAN_PORTS, set())

    def test_all_requested_settings_are_swept_without_hidden_retries(self):
        worker = discovery.SerialParamScanWorker("COM8", "rtu", 1, 2, 0.2,
                                                 baud_rates=[9600, 19200])
        worker._probe_pause = lambda _baud: None
        clients, progress, completed = [], [], []

        def factory(**kwargs):
            client = FakeClient([{"category": "timeout"}])
            clients.append((kwargs, client))
            return client

        worker.progress.connect(progress.append)
        worker.scan_complete.connect(completed.append)
        with patch.object(discovery, "ModbusClient", side_effect=factory):
            worker.run()
        self.assertEqual(len(clients), 2 * 3 * 2 * 2)
        self.assertEqual(progress[-1], 100)
        self.assertEqual(completed, [0])
        self.assertTrue(all(client.closed == 1 and len(client.calls) == 1 and kwargs["retries"] == 0
                            for kwargs, client in clients))

    def test_unsupported_physical_settings_are_skipped_once_then_sweep_continues(self):
        worker = discovery.SerialParamScanWorker("COM8", "rtu", 1, 3, 0.2,
                                                 baud_rates=[600, 9600])
        worker._probe_pause = lambda _baud: None
        calls, evidence = [], []

        def factory(**kwargs):
            calls.append(kwargs)
            return FakeClient([{"result": [42]}] * 2, connected=kwargs["baudrate"] == 9600)

        worker.combo_evidence.connect(evidence.append)
        with patch.object(discovery, "ModbusClient", side_effect=factory), \
                patch.object(discovery, "PARITIES_TO_TRY", ["N"]), \
                patch.object(discovery, "STOPBITS_TO_TRY", [1]):
            worker.run()
        self.assertEqual([call["baudrate"] for call in calls], [600, 9600, 9600, 9600])
        self.assertEqual([reply["unit_id"] for reply in evidence], [1, 2, 3])

    def test_bounds_and_baud_list_validation(self):
        self.assertEqual(discovery.parse_baud_rates("9600, 600, 9600, 76800"), [9600, 600, 76800])
        for text in ("", "9600,", "9600.0", "0", "-1", "4000001"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                discovery.parse_baud_rates(text)
        for start, end in ((0, 1), (1, 248), (2, 1)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                discovery.SerialParamScanWorker("COM8", "rtu", start, end, 0.2)

    def test_low_baud_timeout_includes_actual_request_and_reply_wire_time(self):
        self.assertAlmostEqual(discovery.serial_probe_timeout(600, "E", 1, "rtu", 0.2),
                               0.2 + 15 * 11 / 600 + 3.5 * 11 / 600)
        self.assertAlmostEqual(discovery.serial_probe_timeout(600, "E", 2, "ascii", 0.2),
                               0.2 + 32 * 12 / 600)

    def test_both_dialogs_retain_probe_evidence_in_results_and_csv(self):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication, QWidget
        from gui.network.find_devices import FindDevicesDialog
        from gui.network import find_devices
        from theme import get_colors

        app = QApplication.instance() or QApplication([])
        self.assertIs(find_devices.SerialParamScanWorker, discovery.SerialParamScanWorker)

        class Parent(QWidget):
            def _colors(self):
                return get_colors("light")

            def _get_input_style(self):
                return ""

            def _get_button_style(self):
                return ""

        parent = Parent()
        standalone = discovery.SerialDiscoveryDialog(parent)
        finder = FindDevicesDialog(parent)
        with patch.object(discovery, "detect_serial_ports", return_value=["COM8"]):
            standalone._build_dialog()
            finder._build_dialog()
        worker = self.worker()
        self.run_worker(worker, FakeClient([{"result": [42]}] * 2))
        evidence = self.evidence[0]
        standalone._on_combo_evidence(evidence)
        finder._on_serial_combo_evidence(evidence)
        self.assertEqual(finder.results_table.item(0, 4).text(), "Readable data (2/2 replies)")
        self.assertEqual(standalone.matches_list.item(0).data(discovery.Qt.UserRole + 1), evidence)
        self.assertEqual(finder.results_table.item(0, 0).data(discovery.Qt.UserRole + 1), evidence)
        for dialog in (standalone, finder):
            self.assertEqual((dialog.start_unit_input.minimum(), dialog.end_unit_input.maximum()), (1, 247))
        with patch("gui.csv_export.export_rows_csv") as export:
            standalone._export_matches_csv()
            finder._export_results_csv()
        for call in export.call_args_list:
            headers, rows = call.args[3], call.args[4]
            self.assertEqual(len(headers), len(rows[0]))
            self.assertEqual(rows[0][headers.index("Last RX Hex")], evidence["rx_hex"])
            self.assertEqual(rows[0][headers.index("PDU Address")], 0)
        standalone.dialog.close()
        finder.dialog.close()
        parent.close()
        app.processEvents()


if __name__ == "__main__":
    unittest.main()
