"""Real pymodbus reads against a local, read-only Modbus TCP test peer.

The listener binds only to 127.0.0.1 on an OS-assigned port. No PLC, serial
adapter, external network, or hardware is involved.
"""

import os
from pathlib import Path
import socket
import struct
import sys
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "gui"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication
from core.modbus_client import ModbusClient
from gui.diagnostics import register_scanner as scanner


def register_reply(function, values):
    return bytes((function, len(values) * 2)) + b"".join(
        struct.pack(">H", value) for value in values
    )


class ReadOnlyLoopbackPeer:
    """Minimal TCP framing peer; intentionally independent of pymodbus's server."""

    def __init__(self, responder):
        self.responder = responder
        self.requests = []
        self.errors = []
        self.stop_event = threading.Event()
        self.connection = None

    def __enter__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop_event.set()
        if self.connection is not None:
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.listener.close()
        self.thread.join(2)
        if self.thread.is_alive():
            raise AssertionError("Loopback peer failed to stop")
        if self.errors:
            raise AssertionError(f"Loopback peer failed: {self.errors}")

    def _receive_exactly(self, count):
        data = bytearray()
        while len(data) < count and not self.stop_event.is_set():
            try:
                chunk = self.connection.recv(count - len(data))
            except socket.timeout:
                continue
            if not chunk:
                return None
            data.extend(chunk)
        return bytes(data) if len(data) == count else None

    def _serve(self):
        try:
            while not self.stop_event.is_set():
                try:
                    self.connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    continue
            if self.connection is None:
                return
            with self.connection:
                self.connection.settimeout(0.1)
                while not self.stop_event.is_set():
                    header = self._receive_exactly(7)
                    if header is None:
                        break
                    transaction, protocol, length, unit = struct.unpack(">HHHB", header)
                    pdu = self._receive_exactly(length - 1)
                    if pdu is None:
                        break
                    if protocol != 0 or len(pdu) != 5 or pdu[0] not in (3, 4):
                        raise AssertionError(f"Unexpected or non-read request: {header + pdu!r}")
                    function, address, count = struct.unpack(">BHH", pdu)
                    self.requests.append((unit, function, address, count))
                    replies = self.responder(function, address, count)
                    if isinstance(replies, bytes):
                        replies = [replies]
                    payload = b"".join(
                        struct.pack(">HHHB", transaction, 0, len(reply) + 1, unit) + reply
                        for reply in replies
                    )
                    self.connection.sendall(payload)
        except OSError as error:
            if not self.stop_event.is_set():
                self.errors.append(error)
        except Exception as error:
            self.errors.append(error)


class ModbusLoopbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt_app = QApplication.instance() or QApplication([])

    def connect_client(self, peer):
        client = ModbusClient(ip="127.0.0.1", port=peer.port, unit_id=7,
                              timeout=0.5, retries=0)
        self.assertTrue(client.connect(), client.last_error)
        self.addCleanup(client.disconnect)
        return client

    def scan(self, client, function, start, end, **kwargs):
        worker = scanner.AddressScanWorker(client, function, start, end, 0.2, **kwargs)
        raw, found, rejected, completed = [], [], [], []
        worker.registers_found.connect(lambda address, words: raw.append((address, words)))
        worker.range_found.connect(lambda address, count: found.append((address, count)))
        worker.range_exception.connect(lambda address, code: rejected.append((address, code)))
        worker.scan_complete.connect(lambda *counts: completed.append(counts))
        original_timeout = client.get_timeout()
        with patch.object(scanner, "PROBE_DELAY_MS", 0):
            worker.run()
        self.assertEqual(client.get_timeout(), original_timeout)
        return raw, found, rejected, completed

    def test_fc03_capture_matches_actual_tcp_words_and_zero_based_requests(self):
        words = {10: 0x3F80, 11: 0, 12: 0xFFFF, 13: 0x8000}

        def respond(function, address, count):
            return register_reply(function, [words[index] for index in range(address, address + count)])

        with ReadOnlyLoopbackPeer(respond) as peer:
            client = self.connect_client(peer)
            raw, found, rejected, completed = self.scan(
                client, "Holding Registers", 10, 13, block_size=2
            )
            self.assertEqual(peer.requests, [(7, 3, 10, 2), (7, 3, 12, 2)])
            self.assertEqual(raw, [(10, [0x3F80, 0]), (12, [0xFFFF, 0x8000])])
            self.assertEqual(found, [(10, 2), (12, 2)])
            self.assertEqual(rejected, [])
            self.assertEqual(completed, [(4, 2, 0)])
            self.assertEqual(client.last_tx_bytes[-5:], struct.pack(">BHH", 3, 12, 2))
            self.assertEqual(client.last_rx_bytes[-6:], bytes.fromhex("03 04 FF FF 80 00"))
            client.disconnect()

    def test_fc04_uses_input_register_function_and_maximum_wire_address(self):
        with ReadOnlyLoopbackPeer(lambda function, *_: register_reply(function, [0xABCD])) as peer:
            client = self.connect_client(peer)
            raw, found, rejected, completed = self.scan(client, "Input Registers", 65535, 65535)
            self.assertEqual(peer.requests, [(7, 4, 65535, 1)])
            self.assertEqual(raw, [(65535, [0xABCD])])
            self.assertEqual(found, [(65535, 1)])
            self.assertEqual(rejected, [])
            self.assertEqual(completed, [(1, 1, 0)])
            client.disconnect()

    def test_real_exception_reply_bisects_without_bridging_unreadable_register(self):
        words = {10: 100, 11: 200, 13: 400}

        def respond(function, address, count):
            if any(index not in words for index in range(address, address + count)):
                return bytes((function | 0x80, 2))
            return register_reply(function, [words[index] for index in range(address, address + count)])

        with ReadOnlyLoopbackPeer(respond) as peer:
            client = self.connect_client(peer)
            with self.assertLogs("core.modbus_client", level="ERROR"):
                raw, found, rejected, completed = self.scan(client, "Holding Registers", 10, 13)
            self.assertEqual(peer.requests, [
                (7, 3, 10, 4), (7, 3, 10, 2), (7, 3, 12, 2), (7, 3, 12, 1), (7, 3, 13, 1),
            ])
            self.assertEqual(raw, [(10, [100, 200]), (13, [400])])
            self.assertEqual(found, [(10, 2), (13, 1)])
            self.assertEqual(rejected, [(12, 2)])
            self.assertEqual(completed, [(3, 5, 0)])
            client.disconnect()

    def test_reply_guard_skips_wrong_register_count_and_accepts_matching_frame(self):
        def respond(function, *_):
            return [register_reply(function, [0xDEAD]),
                    register_reply(function, [0x1234, 0x5678])]

        with ReadOnlyLoopbackPeer(respond) as peer:
            client = self.connect_client(peer)
            raw, found, rejected, completed = self.scan(client, "Holding Registers", 20, 21)
            self.assertEqual(peer.requests, [(7, 3, 20, 2)])
            self.assertEqual(raw, [(20, [0x1234, 0x5678])])
            self.assertEqual(found, [(20, 2)])
            self.assertEqual(rejected, [])
            self.assertEqual(completed, [(2, 1, 0)])
            self.assertEqual(client.foreign_replies_skipped, 1)
            self.assertEqual(client.last_rx_bytes[-6:], bytes.fromhex("03 04 12 34 56 78"))
            client.disconnect()


if __name__ == "__main__":
    unittest.main()
