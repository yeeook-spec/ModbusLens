"""Paged, offline register interpretations from a frozen scanner capture."""

import math

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDialog, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QPushButton, QSpinBox, QTableWidget,
    QTableWidgetItem, QVBoxLayout,
)

from core.register_analysis import DATA_TYPES, iter_register_candidates
from gui.csv_export import export_rows_csv


class RegisterAnalysisDialog(QDialog):
    PAGE_SIZE = 25

    def __init__(self, registers, start, end, *, device="", unit="", function_name="",
                 one_based=False, parent=None):
        super().__init__(parent)
        if not 0 <= start <= end <= 65535:
            raise ValueError("Analysis range must use PDU addresses 0 through 65535.")
        self.registers = dict(registers)
        self.start_address = start
        self.end_address = end
        self.device = str(device)
        self.unit = str(unit)
        self.function_name = str(function_name)
        self.one_based = bool(one_based)
        self._display_base = int(self.one_based)
        self._page_start = start
        self._page_end = min(end, start + self.PAGE_SIZE - 1)
        self._min_value = None
        self._max_value = None
        self._page_candidates = []
        self.setWindowTitle("Register interpretations — captured scan")
        self.resize(1200, 720)
        self.setMinimumSize(900, 560)
        self._build_ui()
        self._refresh_page()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        metadata = QLabel(
            f"Device: {self.device or '(unspecified)'}    Unit: {self.unit or '(unspecified)'}    "
            f"Function: {self.function_name or '(unspecified)'}"
        )
        metadata.setTextFormat(Qt.TextFormat.PlainText)
        metadata.setWordWrap(True)
        metadata.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        layout.addWidget(metadata)

        convention = "1-based (PDU + 1)" if self.one_based else "0-based (same as PDU)"
        note = QLabel(
            f"Frozen, read-only capture. Reference addresses are {convention}; these are not "
            "Modicon 4xxxx/3xxxx numbers. Each requested reference is tried at offsets −2 through +2. "
            "32-bit values combine two readable consecutive words in each byte/word order. "
            "Scores are heuristic inspection priorities, not proof of type, offset, or order. "
            "Confirm against device documentation, engineering units, and scaling. Missing words are omitted."
        )
        note.setWordWrap(True)
        layout.addWidget(note)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Interpretation:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems(["F32", "All types", "U16", "S16", "U32", "S32"])
        self.type_combo.currentTextChanged.connect(self._refresh_page)
        controls.addWidget(self.type_combo)
        controls.addWidget(QLabel("Expected min:"))
        self.min_edit = QLineEdit()
        self.min_edit.setPlaceholderText("unbounded")
        self.min_edit.setMaximumWidth(115)
        self.min_edit.returnPressed.connect(self._apply_bounds)
        controls.addWidget(self.min_edit)
        controls.addWidget(QLabel("Max:"))
        self.max_edit = QLineEdit()
        self.max_edit.setPlaceholderText("unbounded")
        self.max_edit.setMaximumWidth(115)
        self.max_edit.returnPressed.connect(self._apply_bounds)
        controls.addWidget(self.max_edit)
        self.apply_button = QPushButton("Apply bounds")
        self.apply_button.clicked.connect(self._apply_bounds)
        controls.addWidget(self.apply_button)
        self.within_bounds_only = QCheckBox("Within bounds only")
        self.within_bounds_only.setToolTip("Apply at least one bound before filtering. Values are unscaled.")
        self.within_bounds_only.setEnabled(False)
        self.within_bounds_only.toggled.connect(self._refresh_page)
        controls.addWidget(self.within_bounds_only)
        controls.addStretch()
        layout.addLayout(controls)

        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        self.error_label.hide()
        layout.addWidget(self.error_label)

        paging = QHBoxLayout()
        self.previous_button = QPushButton("Previous 25")
        self.previous_button.clicked.connect(lambda: self.jump_spin.setValue(
            max(self.start_address, self._page_start - self.PAGE_SIZE) + self._display_base))
        paging.addWidget(self.previous_button)
        paging.addWidget(QLabel("Start at reference:"))
        self.jump_spin = QSpinBox()
        self.jump_spin.setRange(self.start_address + self._display_base, self.end_address + self._display_base)
        self.jump_spin.setValue(self.start_address + self._display_base)
        self.jump_spin.setKeyboardTracking(False)
        self.jump_spin.setSingleStep(self.PAGE_SIZE)
        self.jump_spin.valueChanged.connect(self._jump_to_reference)
        paging.addWidget(self.jump_spin)
        self.next_button = QPushButton("Next 25")
        self.next_button.clicked.connect(lambda: self.jump_spin.setValue(
            min(self.end_address, self._page_start + self.PAGE_SIZE) + self._display_base))
        paging.addWidget(self.next_button)
        paging.addStretch()
        self.bounds_label = QLabel("Applied bounds: none (unscaled values)")
        paging.addWidget(self.bounds_label)
        layout.addLayout(paging)

        self.results_table = QTableWidget(0, 9)
        self.results_table.setHorizontalHeaderLabels([
            "Reference", "Exact PDU", "Offset", "Raw words (hex)", "Type", "Order",
            "Decoded value", "Score", "Heuristic evidence",
        ])
        self.results_table.horizontalHeaderItem(0).setToolTip("Requested nominal reference in the selected 0-based/1-based convention.")
        self.results_table.horizontalHeaderItem(1).setToolTip("Zero-based protocol data unit (PDU) address of the first raw word actually decoded.")
        self.results_table.horizontalHeaderItem(5).setToolTip(
            "AB: one register. ABCD: captured bytes unchanged. CDAB: swap words. "
            "BADC: swap bytes within words. DCBA: swap both words and bytes."
        )
        self.results_table.horizontalHeaderItem(7).setToolTip("0–100 inspection priority. This is not a probability or confirmation of the correct interpretation.")
        self.results_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setWordWrap(False)
        self.results_table.verticalHeader().setVisible(False)
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((85, 85, 65, 135, 60, 65, 130, 60, 310)):
            self.results_table.setColumnWidth(column, width)
        header.setToolTip("Reference is the requested address. Exact PDU is the first word actually decoded after the offset.")
        layout.addWidget(self.results_table, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        footer = QHBoxLayout()
        self.export_button = QPushButton("Export current page CSV…")
        self.export_button.setToolTip("Export the visible interpretations on this page, including active filters and provenance.")
        self.export_button.clicked.connect(self._export_current_page)
        footer.addWidget(self.export_button)
        footer.addStretch()
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        footer.addWidget(close_button)
        layout.addLayout(footer)

    @staticmethod
    def _parse_bound(text):
        if not text.strip():
            return None
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("Bounds must be finite numbers.")
        return value

    def _apply_bounds(self):
        try:
            minimum = self._parse_bound(self.min_edit.text())
            maximum = self._parse_bound(self.max_edit.text())
            if minimum is not None and maximum is not None and minimum > maximum:
                raise ValueError("Minimum must not exceed maximum.")
        except ValueError as error:
            self.error_label.setText(f"Bounds error: {error} The previous applied bounds remain in use.")
            self.error_label.show()
            return
        self._min_value, self._max_value = minimum, maximum
        self.error_label.hide()
        has_bounds = minimum is not None or maximum is not None
        self.within_bounds_only.setEnabled(has_bounds)
        if not has_bounds:
            self.within_bounds_only.setChecked(False)
            self.bounds_label.setText("Applied bounds: none (unscaled values)")
        else:
            low = "unbounded" if minimum is None else f"{minimum:g}"
            high = "unbounded" if maximum is None else f"{maximum:g}"
            self.bounds_label.setText(f"Applied bounds: {low} to {high} (unscaled)")
        self._refresh_page()

    def _jump_to_reference(self, reference):
        self._page_start = reference - self._display_base
        self._refresh_page()

    def _refresh_page(self, *_):
        self._page_end = min(self.end_address, self._page_start + self.PAGE_SIZE - 1)
        selected_type = self.type_combo.currentText()
        types = DATA_TYPES if selected_type == "All types" else (selected_type,)
        candidates = iter_register_candidates(
            self.registers, range(self._page_start, self._page_end + 1), data_types=types,
            min_value=self._min_value, max_value=self._max_value,
        )
        self._page_candidates = [
            item for item in candidates
            if not self.within_bounds_only.isChecked() or item.in_range is True
        ]
        self.results_table.setUpdatesEnabled(False)
        try:
            self.results_table.setRowCount(len(self._page_candidates))
            for row, item in enumerate(self._page_candidates):
                values = (
                    str(item.requested_address + self._display_base), str(item.pdu_address),
                    f"{item.offset:+d}", " ".join(f"0x{word:04X}" for word in item.raw_words),
                    item.data_type, item.byte_order,
                    f"{item.value:.9g}" if isinstance(item.value, float) else str(item.value),
                    str(item.score), " ".join(item.reasons),
                )
                for column, value in enumerate(values):
                    cell = QTableWidgetItem(value)
                    cell.setToolTip(repr(item.value) if column == 6 else value)
                    self.results_table.setItem(row, column, cell)
        finally:
            self.results_table.setUpdatesEnabled(True)
        self.previous_button.setEnabled(self._page_start > self.start_address)
        self.next_button.setEnabled(self._page_end < self.end_address)
        self.export_button.setEnabled(bool(self._page_candidates))
        self.status_label.setText(
            f"References {self._page_start + self._display_base}–{self._page_end + self._display_base} "
            f"of {self.start_address + self._display_base}–{self.end_address + self._display_base}: "
            f"{len(self._page_candidates):,} interpretations. Ranked within each requested reference. "
            "No rows means no complete readable words for the selected type/filter."
        )

    def _export_current_page(self):
        header = [
            "Device", "Unit ID", "Function", "Reference convention", "Scan start PDU", "Scan end PDU",
            "Page start PDU", "Page end PDU", "Requested reference", "Requested PDU", "Exact PDU",
            "Offset", "Raw words hex", "Data type", "Byte/word order", "Decoded value",
            "Heuristic score", "Heuristic evidence", "Expected minimum (unscaled)",
            "Expected maximum (unscaled)", "Within expected bounds", "Within bounds only filter",
            "Interpretation filter", "Evidence limitation",
        ]
        rows = []
        for item in self._page_candidates:
            rows.append([
                self.device, self.unit, self.function_name,
                "1-based (PDU + 1)" if self.one_based else "0-based (same as PDU)",
                self.start_address, self.end_address, self._page_start, self._page_end,
                item.requested_address + self._display_base, item.requested_address, item.pdu_address,
                item.offset, " ".join(f"0x{word:04X}" for word in item.raw_words),
                item.data_type, item.byte_order, repr(item.value), item.score, " ".join(item.reasons),
                "" if self._min_value is None else self._min_value,
                "" if self._max_value is None else self._max_value,
                "" if item.in_range is None else item.in_range, self.within_bounds_only.isChecked(),
                self.type_combo.currentText(),
                "Heuristic inspection priority only; confirm documentation, units and scaling.",
            ])
        return export_rows_csv(self, "Export current analysis page CSV", "register_analysis_page", header, rows)
