from math import ceil
from threading import Lock

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
    QComboBox, QSpinBox, QProgressBar, QListWidget, QListWidgetItem, QWidget, QLineEdit,
)

from core.modbus_client import ModbusClient
from theme import apply_dropdown_delegate

# Floor between any two connection attempts, regardless of how short the per-trial
# timeout is configured -- mirrors the Script tab's MIN_STEP_INTERVAL_MS and the
# Network Scanner's 50ms IP-probe delay: a fast timeout shouldn't turn into flooding.
PROBE_DELAY_MS = 20
_ACTIVE_SCAN_PORTS = set()
_SCAN_PORT_LOCK = Lock()


def modbus_rtu_t35_ms(baud):
    """Modbus RTU's own minimum inter-frame silent interval (3.5 character times).
    Fixed at 1.75ms above 19200 baud per spec; below that it scales with the baud rate,
    using the spec's own fixed 11-bit character time (start + 8 data + parity/stop)
    regardless of the parity/stopbits actually in use -- the spec makes that same
    simplification. At low baud (e.g. 1200) this is well past the flat PROBE_DELAY_MS
    floor above (~32ms vs. 20ms); at anything above ~2400 baud the floor already covers it."""
    if baud > 19200:
        return 1.75
    return (3.5 * 11 / baud) * 1000

# Common serial settings to sweep -- byte size is deliberately not swept, since 8 data
# bits is the near-universal default and a fourth dimension would multiply the already
# large combination count for little benefit.
BAUD_RATES_TO_TRY = [600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 76800, 115200]
PARITIES_TO_TRY = ["N", "E", "O"]
STOPBITS_TO_TRY = [1, 2]

# Human-readable labels for the parity codes above, matching how Connection Settings
# displays them (ConnectionSettingsDialog.PARITIES) -- kept as a local copy since
# main_window importing this module already goes the other way.
PARITY_LABELS = {"N": "None", "E": "Even", "O": "Odd"}

PROBE_FUNCTIONS = {"Holding Registers (FC03)": "holding", "Input Registers (FC04)": "input"}


def parse_baud_rates(text):
    """Preserve the requested order and remove duplicate baud rates."""
    try:
        rates = list(dict.fromkeys(int(value.strip()) for value in text.split(",")))
    except ValueError:
        raise ValueError("Baud rates must be comma-separated whole numbers.") from None
    if not rates or any(rate < 50 or rate > 4000000 for rate in rates):
        raise ValueError("Enter baud rates between 50 and 4000000; adapter support varies.")
    return rates


def serial_probe_timeout(baud, parity, stopbits, framer, reply_wait):
    """Allow one request and one-register response to cross the wire before timing out.

    A serial write may return while its bytes are still transmitting. At 600 baud,
    request/response wire time alone exceeds the usual 200ms device reply wait.
    """
    characters = 32 if framer == "ascii" else 15  # ASCII 17+15; RTU 8+7 bytes
    bits_per_character = 1 + 8 + (parity != "N") + stopbits
    silence = 0 if framer == "ascii" else modbus_rtu_t35_ms(baud) / 1000
    return reply_wait + characters * bits_per_character / baud + silence


class SerialScanOptions(QWidget):
    """The same read-only probe controls in Serial Discovery and Find Devices."""

    def __init__(self, parent_window):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        row = QHBoxLayout()
        row.addWidget(QLabel("Baud rates:"))
        self.baud_input = QLineEdit(", ".join(str(rate) for rate in BAUD_RATES_TO_TRY))
        self.baud_input.setStyleSheet(parent_window._get_input_style())
        self.baud_input.setToolTip("Comma-separated baud rates, tried in this order. All N/E/O parity and 1/2 stop-bit settings are tested.")
        row.addWidget(self.baud_input)
        layout.addLayout(row)
        row = QHBoxLayout()
        self.function_combo = QComboBox()
        self.function_combo.addItems(PROBE_FUNCTIONS)
        self.function_combo.setStyleSheet(parent_window._get_input_style())
        apply_dropdown_delegate(self.function_combo, getattr(parent_window, "_theme_mode", "light"))
        row.addWidget(self.function_combo)
        row.addWidget(QLabel("PDU address:"))
        self.address_input = QSpinBox()
        self.address_input.setRange(0, 65535)
        self.address_input.setStyleSheet(parent_window._get_input_style())
        self.address_input.setToolTip("Zero-based wire address. For example, conventional holding register 40001 is address 0.")
        row.addWidget(self.address_input)
        row.addWidget(QLabel("Confirm replies:"))
        self.confirmations_input = QSpinBox()
        self.confirmations_input.setRange(2, 5)
        self.confirmations_input.setValue(2)
        self.confirmations_input.setStyleSheet(parent_window._get_input_style())
        row.addWidget(self.confirmations_input)
        layout.addLayout(row)
        note = QLabel("Read-only probes. A repeated Modbus exception confirms communication, not readable register data.")
        note.setWordWrap(True)
        layout.addWidget(note)

    def scan_options(self):
        return {
            "baud_rates": parse_baud_rates(self.baud_input.text()),
            "probe_function": PROBE_FUNCTIONS[self.function_combo.currentText()],
            "probe_address": self.address_input.value(),
            "confirmation_count": self.confirmations_input.value(),
        }


def detect_serial_ports():
    try:
        from serial.tools import list_ports
        ports = [p.device for p in list_ports.comports()]
        if ports:
            return ports
    except Exception:
        pass
    return ["COM1", "COM2", "COM3", "COM4"]


class SerialParamScanWorker(QThread):
    """Tries common baud rate / parity / stop-bit / Unit ID combinations against a
    serial port to find which one a device actually speaks, for when its settings
    aren't documented. Opens and closes its own short-lived connection per combination,
    since testing a physical serial setting means actually reopening the port with it --
    that also means it can't run while ModbusLens (or anything else) already holds the
    same port open."""

    combo_matched = Signal(int, str, int, int)  # baud, parity, stopbits, unit_id
    combo_evidence = Signal(dict)
    progress = Signal(int)
    output = Signal(str)
    scan_complete = Signal(int)  # matches found

    def __init__(self, serial_port, framer, start_unit, end_unit, per_trial_timeout,
                 probe_function="holding", probe_address=0, confirmation_count=2, baud_rates=None):
        super().__init__()
        if not 1 <= start_unit <= end_unit <= 247:
            raise ValueError("Serial Unit IDs must be between 1 and 247 (0 is broadcast).")
        if probe_function not in ("holding", "input") or not 0 <= probe_address <= 65535:
            raise ValueError("Choose FC03/FC04 and a PDU address between 0 and 65535.")
        if not 2 <= confirmation_count <= 5 or per_trial_timeout <= 0:
            raise ValueError("Use 2 to 5 confirmation replies and a positive timeout.")
        self.serial_port = serial_port
        self.framer = framer
        self.start_unit = start_unit
        self.end_unit = end_unit
        self.per_trial_timeout = per_trial_timeout
        self.probe_function = probe_function
        self.probe_address = probe_address
        self.confirmation_count = confirmation_count
        self.baud_rates = parse_baud_rates(",".join(str(rate) for rate in (BAUD_RATES_TO_TRY if baud_rates is None else baud_rates)))
        self.should_stop = False

    def stop(self):
        self.should_stop = True

    def run(self):
        port_key = self.serial_port.strip().casefold()
        with _SCAN_PORT_LOCK:
            busy = port_key in _ACTIVE_SCAN_PORTS
            if not busy:
                _ACTIVE_SCAN_PORTS.add(port_key)
        if busy:
            self.output.emit(f"A serial discovery scan is already running on {self.serial_port}. Stop it first.")
            self.scan_complete.emit(0)
            return
        combos = [
            (baud, parity, stopbits, unit_id)
            for baud in self.baud_rates
            for parity in PARITIES_TO_TRY
            for stopbits in STOPBITS_TO_TRY
            for unit_id in range(self.start_unit, self.end_unit + 1)
        ]
        total = len(combos)
        matches = 0
        aborted = False
        failed_settings = set()
        opened_any = False
        try:
            for i, (baud, parity, stopbits, unit_id) in enumerate(combos):
                if self.should_stop:
                    break
                setting = (baud, parity, stopbits)
                if setting in failed_settings:
                    self.progress.emit(int((i + 1) / total * 100))
                    continue
                label = f"{baud} baud, parity={parity}, stop bits={stopbits}, Unit {unit_id}"
                client = ModbusClient(
                    unit_id=unit_id, timeout=serial_probe_timeout(
                        baud, parity, stopbits, self.framer, self.per_trial_timeout), retries=0,
                    mode="serial", serial_port=self.serial_port, baudrate=baud,
                    parity=parity, stopbits=stopbits, bytesize=8, serial_framer=self.framer,
                )
                evidence = None
                try:
                    if not client.connect():
                        failed_settings.add(setting)
                        self.output.emit(
                            f"Skipping {baud}/{parity}/8/{stopbits}: could not open {self.serial_port}: "
                            f"{client.last_error or 'unknown error'}."
                        )
                    else:
                        opened_any = True
                        evidence = self._confirm_probe(client, baud)
                finally:
                    client.disconnect()
                if evidence and not self.should_stop:
                    matches += 1
                    evidence.update(serial_port=self.serial_port, framer=self.framer,
                                    baudrate=baud, parity=parity, stopbits=stopbits, unit_id=unit_id)
                    self.combo_matched.emit(baud, parity, stopbits, unit_id)
                    self.combo_evidence.emit(evidence)
                    self.output.emit(f"  {evidence['summary']}: {label}; FC{evidence['function_code']:02d} "
                                     f"address {self.probe_address}; TX {evidence['tx_hex'] or '(not captured)'}; "
                                     f"RX {evidence['rx_hex'] or '(not captured)'}")
                self.progress.emit(int((i + 1) / total * 100))
                self._probe_pause(baud)
            if not opened_any and not self.should_stop:
                aborted = True
                self.output.emit("No serial settings could be opened. Check port access and adapter support.")
        except Exception as exc:
            aborted = True
            self.output.emit(f"Scan failed: {exc}")
        finally:
            with _SCAN_PORT_LOCK:
                _ACTIVE_SCAN_PORTS.discard(port_key)
            self.output.emit("Scan stopped." if self.should_stop else "Scan aborted." if aborted else "Scan complete.")
            self.scan_complete.emit(matches)

    def _probe_pause(self, baud):
        self.msleep(ceil(max(PROBE_DELAY_MS, modbus_rtu_t35_ms(baud))))

    def _confirm_probe(self, client, baud):
        data_replies, exception_codes = 0, []
        registers = []
        for attempt in range(self.confirmation_count):
            if self.should_stop:
                return None
            read = client.read_registers if self.probe_function == "holding" else client.read_input_registers
            result = read(self.probe_address, 1)
            # pymodbus validates frame CRC/LRC, unit and function; ModbusClient's reply
            # guard also rejects the wrong register count. Raw RX alone is not proof.
            if (isinstance(result, (list, tuple)) and len(result) == 1
                    and type(result[0]) is int and 0 <= result[0] <= 65535):
                data_replies += 1
                registers = list(result)
            elif (client.last_error_category == "device_exception"
                  and client.last_exception_code is not None):
                exception_codes.append(client.last_exception_code)
            else:
                if attempt:
                    self.output.emit(f"  Unconfirmed reply: {attempt}/{self.confirmation_count} valid responses; "
                                     f"{client.last_error or 'no valid reply'}")
                return None
            if attempt + 1 < self.confirmation_count:
                self._probe_pause(baud)
        summary = (f"Readable data ({data_replies}/{self.confirmation_count} replies)"
                   if data_replies == self.confirmation_count else
                   f"Protocol replies ({data_replies} data, exceptions {','.join(map(str, exception_codes))})")
        return {
            "probe_address": self.probe_address, "function_code": 3 if self.probe_function == "holding" else 4,
            "confirmations": self.confirmation_count, "data_replies": data_replies,
            "registers": registers, "exception_codes": exception_codes, "summary": summary,
            "tx_hex": (client.last_tx_bytes or b"").hex(" ").upper(),
            "rx_hex": (client.last_rx_bytes or b"").hex(" ").upper(),
        }


class SerialDiscoveryDialog:
    """Diagnostics > Serial Discovery: sweeps common baud rate/parity/stop-bit/Unit ID
    combinations against a COM port to find which one a device actually speaks. Doesn't
    reuse the app's shared connection -- it opens its own for each combination, since
    testing a physical serial setting means actually reopening the port with it, so it
    can't run while ModbusLens's own connection (or anything else) holds the same port."""

    def __init__(self, parent_window):
        self.parent = parent_window
        self.dialog = None
        self.worker = None
        self.output_text = None

    def show_discovery(self, initial_port=None):
        if self.dialog is None:
            self._build_dialog()
        if initial_port:
            self.port_combo.setCurrentText(initial_port)
        self.dialog.show()
        self.dialog.raise_()
        self.dialog.activateWindow()

    def _build_dialog(self):
        c = self.parent._colors()
        self.dialog = QDialog(self.parent)
        self.dialog.setWindowTitle("Serial Discovery")
        self.dialog.setGeometry(300, 300, 780, 630)
        self.dialog.closeEvent = self._on_dialog_close

        layout = QVBoxLayout(self.dialog)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("COM Port:"))
        self.port_combo = QComboBox()
        self.port_combo.setEditable(True)
        self.port_combo.setStyleSheet(self.parent._get_input_style())
        self.port_combo.addItems(detect_serial_ports())
        row1.addWidget(self.port_combo)
        apply_dropdown_delegate(self.port_combo, getattr(self.parent, "_theme_mode", "light"))

        row1.addWidget(QLabel("Framing:"))
        self.framer_combo = QComboBox()
        self.framer_combo.setStyleSheet(self.parent._get_input_style())
        self.framer_combo.addItems(["RTU", "ASCII"])
        row1.addWidget(self.framer_combo)
        apply_dropdown_delegate(self.framer_combo, getattr(self.parent, "_theme_mode", "light"))
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Start Unit ID:"))
        self.start_unit_input = QSpinBox()
        self.start_unit_input.setStyleSheet(self.parent._get_input_style())
        self.start_unit_input.setRange(1, 247)
        self.start_unit_input.setValue(1)
        row2.addWidget(self.start_unit_input)

        row2.addWidget(QLabel("End Unit ID:"))
        self.end_unit_input = QSpinBox()
        self.end_unit_input.setStyleSheet(self.parent._get_input_style())
        self.end_unit_input.setRange(1, 247)
        self.end_unit_input.setValue(1)
        row2.addWidget(self.end_unit_input)

        row2.addWidget(QLabel("Reply wait (ms):"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setStyleSheet(self.parent._get_input_style())
        self.timeout_input.setRange(50, 2000)
        self.timeout_input.setValue(200)
        self.timeout_input.setToolTip("Device response allowance. Request/reply wire time is added automatically, especially for low baud rates.")
        row2.addWidget(self.timeout_input)
        layout.addLayout(row2)
        self.scan_options = SerialScanOptions(self.parent)
        layout.addWidget(self.scan_options)

        row3 = QHBoxLayout()
        row3.addStretch()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setStyleSheet(self.parent._get_button_style())
        self.start_btn.clicked.connect(self._start_scan)
        row3.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setStyleSheet(self.parent._get_button_style())
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_scan)
        row3.addWidget(self.stop_btn)
        layout.addLayout(row3)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        layout.addWidget(QLabel("Matches found (select one, then Apply):"))
        self.matches_list = QListWidget()
        self.matches_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
            }}
        """)
        self.matches_list.setMaximumHeight(90)
        self.matches_list.itemSelectionChanged.connect(self._on_match_selection_changed)
        self.matches_list.itemDoubleClicked.connect(lambda _item: self._apply_selected_match())
        layout.addWidget(self.matches_list)

        apply_row = QHBoxLayout()
        apply_row.addStretch()
        self.export_btn = QPushButton("Export CSV...")
        self.export_btn.setStyleSheet(self.parent._get_button_style())
        self.export_btn.setEnabled(False)
        self.export_btn.setToolTip("Save every match found so far to a CSV file")
        self.export_btn.clicked.connect(self._export_matches_csv)
        apply_row.addWidget(self.export_btn)
        self.apply_btn = QPushButton("Apply to Device...")
        self.apply_btn.setStyleSheet(self.parent._get_button_style())
        self.apply_btn.setEnabled(False)
        self.apply_btn.clicked.connect(self._apply_selected_match)
        apply_row.addWidget(self.apply_btn)
        layout.addLayout(apply_row)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.document().setMaximumBlockCount(5000)
        self.output_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {c["surface"]};
                color: {c["text"]};
                border: 1px solid {c["border"]};
                font-family: 'Consolas', 'Monaco', monospace;
                font-size: 11px;
            }}
        """)
        layout.addWidget(self.output_text, 1)

        button_row = QHBoxLayout()
        button_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(self.parent._get_button_style())
        close_btn.clicked.connect(self.dialog.close)
        button_row.addWidget(close_btn)
        layout.addLayout(button_row)

    def _start_scan(self):
        if self.worker and self.worker.isRunning():
            self.output_text.append("A scan is already running -- wait for it to finish first.")
            return

        port = self.port_combo.currentText().strip()
        if not port:
            self.output_text.append("Enter or select a COM port first.")
            return

        if self.parent._serial_port_in_use(port):
            # This worker opens its own connection per combination instead of reusing
            # the shared one (see class docstring) -- on the same port as the app's live
            # connection, every open attempt would just fail against the OS's exclusive
            # serial lock, wasting the whole sweep on false negatives instead of the
            # real settings. Catching it here gives a clear reason instead of a scan
            # that silently "finds" nothing.
            self.output_text.append(
                f"{port} is in use by a connected device -- disconnect it first, or scan a different port."
            )
            return

        start_unit = self.start_unit_input.value()
        end_unit = self.end_unit_input.value()
        if start_unit > end_unit:
            self.output_text.append("Start Unit ID must not be greater than End Unit ID.")
            return

        try:
            options = self.scan_options.scan_options()
        except ValueError as exc:
            self.output_text.append(str(exc))
            return

        total_combos = (
            len(options["baud_rates"]) * len(PARITIES_TO_TRY) * len(STOPBITS_TO_TRY)
            * (end_unit - start_unit + 1)
        )
        self.output_text.append(f"Scanning serial settings on {port} ({total_combos} combination(s))...")
        self.matches_list.clear()
        self.apply_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_inputs_enabled(False)

        self.worker = SerialParamScanWorker(
            port, self.framer_combo.currentText().lower(), start_unit, end_unit,
            self.timeout_input.value() / 1000.0, **options,
        )
        self.worker.combo_evidence.connect(self._on_combo_evidence)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.output.connect(self.output_text.append)
        self.worker.scan_complete.connect(self._on_scan_complete)
        self.worker.start()

    def _set_inputs_enabled(self, enabled):
        for widget in (self.port_combo, self.framer_combo, self.start_unit_input,
                       self.end_unit_input, self.timeout_input, self.scan_options):
            widget.setEnabled(enabled)

    def _on_combo_evidence(self, evidence):
        port, framer_value = evidence["serial_port"], evidence["framer"]
        baud, parity, stopbits, unit_id = (evidence[key] for key in ("baudrate", "parity", "stopbits", "unit_id"))
        parity_label = PARITY_LABELS.get(parity, parity)
        item = QListWidgetItem(
            f"{port} @ {baud} baud ({parity_label} parity, 8/{stopbits}, "
            f"{framer_value.upper()}, Unit {unit_id}) — {evidence['summary']}"
        )
        item.setData(Qt.UserRole, (port, baud, parity, stopbits, unit_id, framer_value))
        item.setData(Qt.UserRole + 1, evidence)
        item.setToolTip(f"FC{evidence['function_code']:02d}, PDU address {evidence['probe_address']}; "
                        f"registers {evidence['registers']}; TX {evidence['tx_hex']}; RX {evidence['rx_hex']}")
        self.matches_list.addItem(item)
        self.export_btn.setEnabled(True)

    def _export_matches_csv(self):
        rows = []
        for i in range(self.matches_list.count()):
            item = self.matches_list.item(i)
            port, baud, parity, stopbits, unit_id, framer = item.data(Qt.UserRole)
            evidence = item.data(Qt.UserRole + 1)
            rows.append([port, baud, PARITY_LABELS.get(parity, parity), stopbits, framer.upper(), unit_id,
                         evidence["summary"], evidence["function_code"], evidence["probe_address"],
                         evidence["confirmations"], evidence["registers"], evidence["exception_codes"],
                         evidence["tx_hex"], evidence["rx_hex"]])
        if not rows:
            return
        from gui.csv_export import export_rows_csv
        export_rows_csv(
            self.dialog, "Export Serial Discovery Matches", "serial_matches",
            ["Port", "Baud Rate", "Parity", "Stop Bits", "Framing", "Unit ID", "Evidence",
             "Function Code", "PDU Address", "Confirmed Replies", "Last Data Registers", "Exception Codes",
             "Last TX Hex", "Last RX Hex"], rows,
            log=getattr(self.parent, "_log", None),
        )

    def _on_match_selection_changed(self):
        self.apply_btn.setEnabled(self.matches_list.currentItem() is not None)

    def _apply_selected_match(self):
        """Hand a chosen match to Connection Settings, pre-filled but not yet saved --
        mirrors picking a Recent Connections entry there: Save Settings is still the
        deliberate action that commits it, this just fills the form."""
        item = self.matches_list.currentItem()
        if item is None:
            return
        port, baud, parity, stopbits, unit_id, framer = item.data(Qt.UserRole)
        self.stop_all_scans()
        self.dialog.hide()
        self.parent._show_connection_settings(serial_overrides={
            "serial_port": port,
            "baudrate": baud,
            "parity": parity,
            "stopbits": stopbits,
            "unit_id": unit_id,
            "framer": framer,
        })

    def _stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()

    def _on_scan_complete(self, matches_found):
        self.output_text.append(f"Summary: {matches_found} combination(s) with repeated valid replies; see data/exception evidence.")
        self.progress_bar.setVisible(False)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._set_inputs_enabled(True)

    def stop_all_scans(self):
        """Called when the main window is closing (or the dialog itself is), so an
        in-progress scan doesn't keep a QThread running -- and, on app exit, doesn't get
        torn down by Qt/Python mid-run, which can abort the process. Blocks until the
        worker has actually exited (it checks should_stop at least once per trial, so
        this returns within one probe timeout, not indefinitely)."""
        self._stop_scan()
        if self.worker and self.worker.isRunning():
            self.worker.wait(10000)

    def _on_dialog_close(self, event):
        self.stop_all_scans()
        event.accept()
