"""Scanner UI integration: address basis, capture boundaries and frozen exports."""
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gui"))

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QWidget
from gui.diagnostics.register_scanner import RegisterScannerWidget
from theme import LIGHT


class Client:
    unit_id = 7
    last_exception_code = None
    last_error_category = None
    last_error = None

    def __init__(self):
        self.timeout = 1.5
        self.calls = []

    def is_connected(self):
        return True

    def target_description(self):
        return "test fixture"

    def get_timeout(self):
        return self.timeout

    def set_timeout(self, value):
        self.timeout = value

    def read_registers(self, address, count):
        self.calls.append((address, count))
        return [{9: 0x422A, 10: 0}.get(a, a) for a in range(address, address + count)]


class Parent(QWidget):
    _theme_mode = "light"

    def __init__(self):
        super().__init__()
        self.tag_devices = [{"name": "Test PLC", "unit": 7}]
        self.client = Client()
        self.logs = []

    def _colors(self):
        return LIGHT

    def _get_input_style(self):
        return ""

    def _get_button_style(self):
        return ""

    def _device_view(self, name):
        return self.client

    def _device(self, name):
        return self.tag_devices[0]

    def _log(self, message):
        self.logs.append(message)


class ScannerWidgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.parent = Parent()
        self.widget = RegisterScannerWidget(self.parent)

    def tearDown(self):
        self.widget.stop_all_scans()
        self.parent.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        self.app.processEvents()

    def scan(self, start, end):
        self.widget.addr_start_input.setValue(start)
        self.widget.addr_end_input.setValue(end)
        self.widget._start_address_scan()
        self.assertFalse(self.widget.addr_start_input.isEnabled())
        self.assertFalse(self.widget.clear_results_btn.isEnabled())
        self.assertTrue(self.widget.address_worker.wait(3000))
        self.app.processEvents()

    def test_capture_halo_is_bounded_and_not_imported_as_nominal_tags(self):
        self.scan(10, 10)
        self.assertEqual(self.parent.client.calls, [(8, 6)])
        self.assertEqual(self.widget._nominal_range, (10, 10))
        self.assertEqual(self.widget._found_ranges, [(10, 1)])
        self.assertEqual(self.widget._raw_registers[9], 0x422A)
        self.assertEqual(self.parent.client.timeout, 1.5)
        self.assertTrue(self.widget.analysis_capture_checkbox.isEnabled())
        self.assertTrue(self.widget.analyze_btn.isEnabled())
        self.assertTrue(any("1 readable nominal" in line for line in self.parent.logs))
        with patch("gui.diagnostics.register_analysis_dialog.RegisterAnalysisDialog") as dialog:
            self.widget._show_register_analysis()
        self.assertEqual(dialog.call_args.args[1:], (10, 10))
        self.assertEqual(dialog.call_args.kwargs["unit"], 7)

    def test_basis_toggle_preserves_pdu_range_including_last_address(self):
        self.widget.addr_start_input.setValue(65535)
        self.widget.addr_end_input.setValue(65535)
        self.widget.address_basis_combo.setCurrentIndex(1)
        self.assertEqual(self.widget.addr_start_input.value(), 65536)
        self.scan(65536, 65536)
        self.assertEqual(self.parent.client.calls, [(65533, 3)])
        self.assertEqual(self.widget._nominal_range, (65535, 65535))
        self.widget.address_basis_combo.setCurrentIndex(0)
        self.assertEqual(self.widget.addr_end_input.value(), 65535)

    def test_export_preserves_capture_basis_unit_function_and_raw_words(self):
        self.widget.address_basis_combo.setCurrentIndex(1)
        self.scan(11, 11)
        self.widget.address_basis_combo.setCurrentIndex(0)
        self.widget.addr_function_combo.setCurrentText("Input Registers")
        self.parent.tag_devices[0]["unit"] = 99
        with patch("gui.csv_export.export_rows_csv") as export:
            self.widget._export_results_csv()
        header, rows = export.call_args.args[3:5]
        records = [dict(zip(header, row)) for row in rows]
        nominal = next(row for row in records if row["Scope"] == "Nominal")
        self.assertEqual(nominal["Protocol Address"], 10)
        self.assertEqual(nominal["Reference Address"], 11)
        self.assertEqual(nominal["Unit ID"], 7)
        self.assertEqual(nominal["Function"], "Holding Registers")
        self.assertEqual(nominal["Raw Hex"], "0000")

    def test_disabling_neighbour_capture_and_coils_does_not_fake_float_data(self):
        self.widget.analysis_capture_checkbox.setChecked(False)
        self.scan(0, 0)
        self.assertEqual(self.parent.client.calls, [(0, 1)])
        self.widget.addr_function_combo.setCurrentText("Coils")
        self.assertFalse(self.widget.analysis_capture_checkbox.isEnabled())
        self.widget._clear_results()
        self.assertEqual(self.widget._raw_registers, {})
        self.assertFalse(self.widget.analyze_btn.isEnabled())


if __name__ == "__main__":
    unittest.main()
