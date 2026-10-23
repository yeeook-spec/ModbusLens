import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import unittest
from unittest.mock import patch

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication

from gui.diagnostics.register_analysis_dialog import RegisterAnalysisDialog


class RegisterAnalysisDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.capture = {address: (0x4148 if address % 2 == 0 else 0) for address in range(104)}
        self.dialog = RegisterAnalysisDialog(
            self.capture, 0, 99, device="Test PLC", unit=7,
            function_name="Holding Registers", one_based=True,
        )
        self.addCleanup(self._destroy_dialog, self.dialog)

    @staticmethod
    def _destroy_dialog(dialog):
        dialog.close()
        dialog.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)

    def test_default_is_float_paged_and_capture_is_frozen(self):
        self.capture[0] = 999
        self.assertEqual(self.dialog.registers[0], 0x4148)
        self.assertEqual(self.dialog.type_combo.currentText(), "F32")
        self.assertEqual((self.dialog._page_start, self.dialog._page_end), (0, 24))
        self.assertFalse(self.dialog.previous_button.isEnabled())
        self.assertTrue(self.dialog.next_button.isEnabled())
        self.assertLessEqual(self.dialog.results_table.rowCount(), 25 * 5 * 4)
        self.assertTrue(all(item.requested_address < 25 for item in self.dialog._page_candidates))

    def test_next_previous_jump_and_last_pdu(self):
        self.dialog.next_button.click()
        self.assertEqual((self.dialog._page_start, self.dialog._page_end, self.dialog.jump_spin.value()), (25, 49, 26))
        self.dialog.previous_button.click()
        self.assertEqual(self.dialog._page_start, 0)
        self.dialog.jump_spin.setValue(100)
        self.assertEqual((self.dialog._page_start, self.dialog._page_end), (99, 99))
        self.assertFalse(self.dialog.next_button.isEnabled())
        other = RegisterAnalysisDialog({65534: 0x4148, 65535: 0}, 65534, 65535, one_based=True)
        self.addCleanup(self._destroy_dialog, other)
        other.jump_spin.setValue(65536)
        self.assertEqual(other._page_start, 65535)
        self.assertTrue(all(item.pdu_address <= 65534 for item in other._page_candidates))

    def test_invalid_bounds_preserve_applied_results(self):
        self.dialog.min_edit.setText("12")
        self.dialog.max_edit.setText("13")
        self.dialog.apply_button.click()
        before = list(self.dialog._page_candidates)
        self.dialog.min_edit.setText("nonsense")
        self.dialog.apply_button.click()
        self.assertFalse(self.dialog.error_label.isHidden())
        self.assertEqual(self.dialog._min_value, 12)
        self.assertEqual(self.dialog._page_candidates, before)
        for low, high in (("14", "13"), ("nan", "13"), ("12", "inf")):
            self.dialog.min_edit.setText(low)
            self.dialog.max_edit.setText(high)
            self.dialog.apply_button.click()
            self.assertEqual(self.dialog._min_value, 12)
            self.assertEqual(self.dialog._max_value, 13)

    def test_bounds_only_and_clearing_bounds(self):
        self.assertFalse(self.dialog.within_bounds_only.isEnabled())
        self.dialog.min_edit.setText("12")
        self.dialog.max_edit.setText("13")
        self.dialog.apply_button.click()
        unfiltered_count = len(self.dialog._page_candidates)
        self.dialog.within_bounds_only.setChecked(True)
        self.assertTrue(self.dialog._page_candidates)
        self.assertLess(len(self.dialog._page_candidates), unfiltered_count)
        self.assertTrue(all(item.in_range is True and item.value == 12.5 for item in self.dialog._page_candidates))
        self.dialog.min_edit.clear()
        self.dialog.max_edit.clear()
        self.dialog.apply_button.click()
        self.assertFalse(self.dialog.within_bounds_only.isChecked())
        self.assertFalse(self.dialog.within_bounds_only.isEnabled())
        self.assertEqual(len(self.dialog._page_candidates), unfiltered_count)

    def test_all_types_and_table_address_provenance(self):
        self.dialog.type_combo.setCurrentText("All types")
        types = {item.data_type for item in self.dialog._page_candidates}
        self.assertEqual(types, {"F32", "U16", "S16", "U32", "S32"})
        for row, item in enumerate(self.dialog._page_candidates):
            self.assertEqual(self.dialog.results_table.item(row, 0).text(), str(item.requested_address + 1))
            self.assertEqual(self.dialog.results_table.item(row, 1).text(), str(item.pdu_address))

    def test_csv_contains_only_current_page_and_applied_provenance(self):
        self.dialog.min_edit.setText("12")
        self.dialog.max_edit.setText("13")
        self.dialog.apply_button.click()
        self.dialog.within_bounds_only.setChecked(True)
        self.dialog.next_button.click()
        self.dialog.min_edit.setText("invalid unapplied draft")
        with patch("gui.diagnostics.register_analysis_dialog.export_rows_csv", return_value="capture.csv") as export:
            self.assertEqual(self.dialog._export_current_page(), "capture.csv")
        _, title, stem, headers, rows = export.call_args.args
        self.assertIn("current", title)
        self.assertEqual(stem, "register_analysis_page")
        self.assertEqual(len(rows), len(self.dialog._page_candidates))
        records = [dict(zip(headers, row)) for row in rows]
        self.assertTrue(records)
        for record in records:
            self.assertEqual((record["Device"], record["Unit ID"], record["Function"]), ("Test PLC", "7", "Holding Registers"))
            self.assertTrue(25 <= record["Requested PDU"] <= 49)
            self.assertEqual(record["Requested reference"], record["Requested PDU"] + 1)
            self.assertEqual(record["Exact PDU"], record["Requested PDU"] + record["Offset"])
            self.assertEqual((record["Expected minimum (unscaled)"], record["Expected maximum (unscaled)"]), (12, 13))
            self.assertTrue(record["Within bounds only filter"])
            address = record["Exact PDU"]
            self.assertEqual(record["Raw words hex"],
                             f"0x{self.capture[address]:04X} 0x{self.capture[address + 1]:04X}")
            self.assertEqual(record["Decoded value"], "12.5")


if __name__ == "__main__":
    unittest.main()
