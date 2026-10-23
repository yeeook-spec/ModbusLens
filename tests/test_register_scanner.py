"""Offline checks for the read-only register scanner's evidence and cleanup rules.

Run from the repository root: python -m unittest discover -s tests -v
"""

from dataclasses import dataclass
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "gui"))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from gui.diagnostics import register_scanner as scanner


@dataclass
class Reply:
    values: object = None
    exception: int | None = None
    category: str | None = None
    error: str = ""


class FakeModbus:
    """Only expose reads: an accidental write cannot succeed in these tests."""

    def __init__(self, handler=None):
        self.handler = handler or (
            lambda function, address, count: Reply(
                [(address + offset) & 0xFFFF for offset in range(count)]
            )
        )
        self.timeout = 2.5
        self.timeout_changes = []
        self.reads = []
        self.last_exception_code = None
        self.last_error_category = None
        self.last_error = ""

    def get_timeout(self):
        return self.timeout

    def set_timeout(self, value):
        self.timeout_changes.append(value)
        self.timeout = value

    def _read(self, function, address, count):
        self.reads.append((function, address, count))
        reply = self.handler(function, address, count)
        self.last_exception_code = reply.exception
        self.last_error_category = reply.category
        self.last_error = reply.error
        return reply.values

    def read_registers(self, address, count):
        return self._read("Holding Registers", address, count)

    def read_input_registers(self, address, count):
        return self._read("Input Registers", address, count)

    def read_coils(self, address, count):
        return self._read("Coils", address, count)

    def read_discrete_inputs(self, address, count):
        return self._read("Discrete Inputs", address, count)


class AddressScanWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.delay_patch = patch.object(scanner, "PROBE_DELAY_MS", 0)
        self.delay_patch.start()
        self.addCleanup(self.delay_patch.stop)

    def make_worker(self, modbus=None, function="Holding Registers", start=10,
                    end=13, **kwargs):
        modbus = modbus or FakeModbus()
        worker = scanner.AddressScanWorker(
            modbus, function, start, end, 0.15, **kwargs
        )
        events = {name: [] for name in (
            "range_found", "registers_found", "range_exception",
            "range_not_responding", "range_inconclusive", "progress",
            "output", "scan_complete",
        )}
        for name, collected in events.items():
            getattr(worker, name).connect(
                lambda *args, target=collected: target.append(args)
            )
        return worker, events, modbus

    def assert_finished(self, events, modbus, counts):
        self.assertEqual(events["scan_complete"], [counts])
        self.assertEqual(modbus.timeout, 2.5)

    def test_success_preserves_raw_registers_and_protocol_addresses(self):
        values = [0x3F80, 0, 0xFFFF, 0x8000]
        worker, events, modbus = self.make_worker(
            FakeModbus(lambda *_: Reply(values)), start=0, end=3
        )
        worker.run()
        self.assertEqual(modbus.reads, [("Holding Registers", 0, 4)])
        self.assertEqual(events["registers_found"], [(0, values)])
        self.assertEqual(events["range_found"], [(0, 4)])
        self.assertEqual(events["progress"][-1], (100,))
        self.assertEqual(events["range_not_responding"], [])
        self.assert_finished(events, modbus, (4, 1, 0))

    def test_input_register_function_dispatches_correct_read(self):
        worker, events, modbus = self.make_worker(function="Input Registers")
        worker.run()
        self.assertEqual(modbus.reads, [("Input Registers", 10, 4)])
        self.assertEqual(events["registers_found"], [(10, [10, 11, 12, 13])])
        self.assert_finished(events, modbus, (4, 1, 0))

    def test_default_register_requests_never_exceed_125(self):
        worker, events, modbus = self.make_worker(start=100, end=350)
        worker.run()
        self.assertEqual(modbus.reads, [
            ("Holding Registers", 100, 125),
            ("Holding Registers", 225, 125),
            ("Holding Registers", 350, 1),
        ])
        self.assert_finished(events, modbus, (251, 3, 0))

    def test_configurable_block_size_limits_each_read(self):
        worker, events, modbus = self.make_worker(start=10, end=14, block_size=2)
        worker.run()
        self.assertEqual(modbus.reads, [
            ("Holding Registers", 10, 2),
            ("Holding Registers", 12, 2),
            ("Holding Registers", 14, 1),
        ])
        self.assert_finished(events, modbus, (5, 3, 0))

    def test_last_protocol_address_is_read_without_overflow(self):
        worker, events, modbus = self.make_worker(start=65535, end=65535)
        worker.run()
        self.assertEqual(modbus.reads, [("Holding Registers", 65535, 1)])
        self.assertEqual(events["registers_found"], [(65535, [65535])])
        self.assert_finished(events, modbus, (1, 1, 0))

    def test_only_unsupported_single_addresses_are_confirmed_bad(self):
        for exception in (2, 3):
            with self.subTest(exception=exception):
                def answer(_function, address, count):
                    if address <= 11 < address + count:
                        return Reply(exception=exception)
                    return Reply(list(range(address, address + count)))

                worker, events, modbus = self.make_worker(FakeModbus(answer))
                worker.run()
                self.assertEqual(modbus.reads, [
                    ("Holding Registers", 10, 4),
                    ("Holding Registers", 10, 2),
                    ("Holding Registers", 10, 1),
                    ("Holding Registers", 11, 1),
                    ("Holding Registers", 12, 2),
                ])
                self.assertEqual(events["range_not_responding"], [(11,)])
                self.assertEqual(events["range_exception"], [(11, exception)])
                self.assertEqual(events["range_inconclusive"], [])
                self.assertEqual(events["registers_found"], [(10, [10]), (12, [12, 13])])
                self.assert_finished(events, modbus, (3, 5, 0))

    def test_busy_or_device_failure_does_not_prove_addresses_invalid(self):
        for exception in (4, 5, 6, 8, 10, 11, 99):
            with self.subTest(exception=exception):
                worker, events, modbus = self.make_worker(
                    FakeModbus(lambda *_: Reply(exception=exception))
                )
                worker.run()
                self.assertEqual(events["range_not_responding"], [])
                self.assertEqual(events["range_exception"], [])
                self.assertEqual(events["range_found"], [])
                self.assertEqual(events["registers_found"], [])
                self.assertEqual(events["range_inconclusive"], [(10,), (11,), (12,), (13,)])
                self.assertEqual(len(modbus.reads), 1)
                self.assert_finished(events, modbus, (0, 1, 4))

    def test_illegal_function_stops_without_false_address_findings(self):
        worker, events, modbus = self.make_worker(
            FakeModbus(lambda *_: Reply(exception=1)), start=0, end=250
        )
        worker.run()
        self.assertEqual(modbus.reads, [("Holding Registers", 0, 125)])
        for signal in ("range_found", "registers_found", "range_exception",
                       "range_not_responding", "range_inconclusive"):
            self.assertEqual(events[signal], [])
        self.assertTrue(any("Illegal Function" in message for (message,) in events["output"]))
        self.assert_finished(events, modbus, (0, 1, 0))

    def test_short_reply_is_retried_in_smaller_blocks_before_success(self):
        def answer(_function, address, count):
            return Reply([address])

        worker, events, modbus = self.make_worker(FakeModbus(answer), end=11)
        worker.run()
        self.assertEqual(modbus.reads, [
            ("Holding Registers", 10, 2),
            ("Holding Registers", 10, 1),
            ("Holding Registers", 11, 1),
        ])
        self.assertEqual(events["range_found"], [(10, 1), (11, 1)])
        self.assertEqual(events["registers_found"], [(10, [10]), (11, [11])])
        self.assert_finished(events, modbus, (2, 3, 0))

    def test_malformed_register_replies_never_create_confirmed_data(self):
        malformed = ([], [1, 2], [-1], [65536], [1.5], [True], ["1"], "1", 1)
        for values in malformed:
            with self.subTest(values=values):
                worker, events, modbus = self.make_worker(
                    FakeModbus(lambda *_: Reply(values)), end=10
                )
                worker.run()
                self.assertEqual(events["range_found"], [])
                self.assertEqual(events["registers_found"], [])
                self.assertEqual(events["range_not_responding"], [])
                self.assertEqual(events["range_exception"], [])
                self.assertEqual(events["range_inconclusive"], [(10,)])
                self.assert_finished(events, modbus, (0, 1, 1))

    def test_no_reply_bisects_then_marks_single_addresses_inconclusive(self):
        worker, events, modbus = self.make_worker(
            FakeModbus(lambda *_: Reply(category="timeout")), end=11
        )
        worker.run()
        self.assertEqual(modbus.reads, [
            ("Holding Registers", 10, 2),
            ("Holding Registers", 10, 1),
            ("Holding Registers", 11, 1),
        ])
        self.assertEqual(events["range_inconclusive"], [(10,), (11,)])
        self.assertEqual(events["range_not_responding"], [])
        self.assertEqual(events["registers_found"], [])
        self.assert_finished(events, modbus, (0, 3, 2))

    def test_connection_failure_stops_without_scanning_rest_of_map(self):
        worker, events, modbus = self.make_worker(
            FakeModbus(lambda *_: Reply(category="connection", error="serial port closed")),
            start=0, end=250,
        )
        worker.run()
        self.assertEqual(modbus.reads, [("Holding Registers", 0, 125)])
        self.assertEqual(events["range_not_responding"], [])
        self.assertEqual(events["range_inconclusive"], [])
        self.assert_finished(events, modbus, (0, 1, 0))

    def test_bit_functions_do_not_emit_register_interpretation_data(self):
        for function in ("Coils", "Discrete Inputs"):
            with self.subTest(function=function):
                worker, events, modbus = self.make_worker(
                    FakeModbus(lambda *_: Reply([True, False, True, False])),
                    function=function,
                )
                worker.run()
                self.assertEqual(modbus.reads, [(function, 10, 4)])
                self.assertEqual(events["range_found"], [(10, 4)])
                self.assertEqual(events["registers_found"], [])
                self.assert_finished(events, modbus, (4, 1, 0))

    def test_cancel_before_first_probe_makes_no_modbus_request(self):
        worker, events, modbus = self.make_worker()
        worker.stop()
        worker.run()
        self.assertEqual(modbus.reads, [])
        self.assertEqual(events["registers_found"], [])
        self.assert_finished(events, modbus, (0, 0, 0))

    def test_actual_qthread_finishes_and_delivers_captured_evidence(self):
        worker, events, modbus = self.make_worker()
        worker.start()
        try:
            self.assertTrue(worker.wait(2000), "Scanner thread did not finish")
            self.qt_app.processEvents()
            self.assertFalse(worker.isRunning())
            self.assertEqual(events["registers_found"], [(10, [10, 11, 12, 13])])
            self.assert_finished(events, modbus, (4, 1, 0))
        finally:
            worker.stop()
            worker.wait(2000)

    def test_cancel_during_read_preserves_completed_reply_and_stops_next_probe(self):
        worker, events, modbus = self.make_worker(block_size=2)

        def answer(_function, address, count):
            worker.stop()
            return Reply(list(range(address, address + count)))

        modbus.handler = answer
        worker.run()
        self.assertEqual(modbus.reads, [("Holding Registers", 10, 2)])
        self.assertEqual(events["registers_found"], [(10, [10, 11])])
        self.assert_finished(events, modbus, (2, 1, 0))

    def test_reservations_are_read_only_and_released_after_each_probe(self):
        reserved, released = [], []
        worker, events, modbus = self.make_worker(
            reserve_range=lambda request: reserved.append(request.copy()) or True,
            release_range=lambda request: released.append(request.copy()),
            block_size=2,
        )
        worker.run()
        self.assertEqual(reserved, released)
        self.assertEqual(len(reserved), 2)
        self.assertEqual(
            [(r["operation"], r["space"], r["start"], r["end"]) for r in reserved],
            [("read", "Holding Register", 10, 11), ("read", "Holding Register", 12, 13)],
        )
        self.assert_finished(events, modbus, (4, 2, 0))

    def test_busy_interlock_retries_without_issuing_a_probe_or_release(self):
        attempts, released = [], []

        def reserve(request):
            attempts.append(request.copy())
            return len(attempts) > 2

        worker, events, modbus = self.make_worker(
            reserve_range=reserve, release_range=lambda request: released.append(request.copy())
        )
        worker.run()
        self.assertEqual(len(attempts), 3)
        self.assertEqual(len(released), 1)
        self.assertEqual(modbus.reads, [("Holding Registers", 10, 4)])
        self.assert_finished(events, modbus, (4, 1, 0))

    def test_stuck_interlock_has_bounded_retries_and_no_wire_requests(self):
        released = []
        worker, events, modbus = self.make_worker(
            reserve_range=lambda _: False, release_range=released.append
        )
        with patch.object(scanner, "MAX_CONSECUTIVE_BUSY_RETRIES", 2):
            worker.run()
        self.assertEqual(modbus.reads, [])
        self.assertEqual(released, [])
        self.assert_finished(events, modbus, (0, 0, 0))

    def test_read_exception_still_releases_range_restores_timeout_and_completes(self):
        released = []

        def raise_read(*_):
            raise OSError("adapter unplugged")

        worker, events, modbus = self.make_worker(
            FakeModbus(raise_read), release_range=released.append
        )
        worker.run()
        self.assertEqual(len(released), 1)
        self.assertEqual(events["registers_found"], [])
        self.assertTrue(events["output"])
        self.assert_finished(events, modbus, (0, 1, 0))

    def test_reservation_failure_restores_timeout_and_completes(self):
        def raise_reserve(_):
            raise RuntimeError("reservation unavailable")

        released = []
        worker, events, modbus = self.make_worker(
            reserve_range=raise_reserve, release_range=released.append
        )
        worker.run()
        self.assertEqual(modbus.reads, [])
        self.assertEqual(released, [])
        self.assert_finished(events, modbus, (0, 0, 0))

    def test_release_failure_still_restores_timeout_and_completes(self):
        def raise_release(_):
            raise RuntimeError("release failed")

        worker, events, modbus = self.make_worker(release_range=raise_release)
        worker.run()
        self.assertEqual(len(events["scan_complete"]), 1)
        self.assertEqual(modbus.timeout, 2.5)
        self.assertTrue(events["output"])

    def test_timeout_setup_failure_still_restores_original_and_completes(self):
        worker, events, modbus = self.make_worker()
        original_set_timeout = modbus.set_timeout

        def fail_probe_timeout(value):
            if value == 0.15:
                raise OSError("cannot set timeout")
            original_set_timeout(value)

        modbus.set_timeout = fail_probe_timeout
        worker.run()
        self.assertEqual(modbus.reads, [])
        self.assert_finished(events, modbus, (0, 0, 0))

    def test_timeout_getter_failure_still_emits_completion_once(self):
        worker, events, modbus = self.make_worker()

        def fail_timeout():
            raise OSError("connection replaced")

        modbus.get_timeout = fail_timeout
        worker.run()
        self.assertEqual(modbus.reads, [])
        self.assertEqual(events["scan_complete"], [(0, 0, 0)])
        self.assertTrue(events["output"])

    def test_timeout_restore_failure_still_emits_completion_once(self):
        worker, events, modbus = self.make_worker()
        original_set_timeout = modbus.set_timeout

        def fail_restore(value):
            if value == 2.5:
                raise OSError("connection closed before restore")
            original_set_timeout(value)

        modbus.set_timeout = fail_restore
        worker.run()
        self.assertEqual(events["scan_complete"], [(4, 1, 0)])
        self.assertTrue(events["output"])


if __name__ == "__main__":
    unittest.main()
