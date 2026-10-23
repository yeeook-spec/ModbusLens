import math
import struct
import unittest

from core.register_analysis import analyze_registers, iter_register_candidates


class RegisterAnalysisTests(unittest.TestCase):
    def test_float_byte_orders_reconstruct_same_known_value(self):
        # Distinct nonzero bytes exercise both swaps, not just zero-filled halves.
        value = 123.456
        raw = struct.pack(">f", value)
        expected = struct.unpack(">f", raw)[0]
        permutations = {
            "ABCD": (0, 1, 2, 3), "CDAB": (2, 3, 0, 1),
            "BADC": (1, 0, 3, 2), "DCBA": (3, 2, 1, 0),
        }
        for order, indices in permutations.items():
            with self.subTest(order=order):
                wire = bytes(raw[index] for index in indices)
                capture = {100: int.from_bytes(wire[:2], "big"), 101: int.from_bytes(wire[2:], "big")}
                candidates = analyze_registers(capture, [100], offsets=(0,), data_types=("F32",))
                candidate = next(item for item in candidates if item.byte_order == order)
                self.assertEqual(candidate.value, expected)
                self.assertEqual(candidate.raw_words, (capture[100], capture[101]))
                self.assertEqual(candidate.pdu_address, 100)

    def test_all_five_offsets_retain_exact_addresses(self):
        capture = {address: address * 10 for address in range(98, 104)}
        candidates = analyze_registers(capture, [100], data_types=("U16",))
        self.assertEqual({item.offset for item in candidates}, {-2, -1, 0, 1, 2})
        for item in candidates:
            self.assertEqual(item.requested_address, 100)
            self.assertEqual(item.pdu_address, 100 + item.offset)
            self.assertEqual(item.raw_words, (capture[item.pdu_address],))
            self.assertEqual(item.value, item.pdu_address * 10)

    def test_signed_unsigned_types(self):
        candidates = analyze_registers({12: 0xFFFE, 13: 0xDCBA}, [12], offsets=(0,), byte_orders=("ABCD",))
        by_type = {item.data_type: item for item in candidates}
        self.assertEqual(by_type["U16"].value, 65534)
        self.assertEqual(by_type["S16"].value, -2)
        self.assertEqual(by_type["U32"].value, 0xFFFEDCBA)
        self.assertEqual(by_type["S32"].value, 0xFFFEDCBA - 2 ** 32)

    def test_missing_and_nonreadable_neighbors_are_not_filled(self):
        candidates = analyze_registers({100: 0x4148, 101: None, 102: 0}, [100, 101], offsets=(0,))
        self.assertEqual({item.data_type for item in candidates}, {"U16", "S16"})
        self.assertTrue(all(item.pdu_address == 100 for item in candidates))
        self.assertEqual(analyze_registers({100: 0x4148, 102: 0}, [100], offsets=(0,), data_types=("F32",)), [])

    def test_pdu_edges_never_wrap_or_pair_beyond_end(self):
        candidates = analyze_registers({0: 20, 1: 10, 65534: 0x4148, 65535: 0}, [0, 65535])
        self.assertTrue(all(0 <= item.pdu_address <= 65535 for item in candidates))
        self.assertTrue(all(item.pdu_address + len(item.raw_words) <= 65536 for item in candidates))
        last = [item for item in candidates if item.pdu_address == 65535]
        self.assertEqual({item.data_type for item in last}, {"U16", "S16"})
        self.assertTrue(any(item.pdu_address == 65534 and item.value == 12.5 for item in candidates))

    def test_section_includes_each_nominal_address(self):
        capture = {address: address for address in range(10, 15)}
        candidates = analyze_registers(capture, range(10, 15), offsets=(0,), data_types=("U16",))
        self.assertEqual([item.requested_address for item in candidates], list(range(10, 15)))

    def test_bounds_rank_matches_without_hiding_outliers(self):
        candidates = analyze_registers({100: 0x4148, 101: 0}, [100], offsets=(0,), min_value=12, max_value=13)
        matches = [item for item in candidates if item.in_range]
        self.assertEqual(len(matches), 1)
        self.assertEqual((matches[0].data_type, matches[0].byte_order, matches[0].value), ("F32", "ABCD", 12.5))
        self.assertEqual(candidates[0], matches[0])
        self.assertTrue(any(item.in_range is False for item in candidates))
        self.assertEqual(len(candidates), 14)

    def test_nonfinite_subnormal_extreme_and_markers_are_explained(self):
        capture = {0: 0x7FC0, 1: 0, 2: 0, 3: 1, 4: 0x7F7F, 5: 0xFFFF, 6: 0, 7: 0, 8: 0xFFFF, 9: 0xFFFF}
        rows = analyze_registers(capture, [0, 2, 4, 6, 8], offsets=(0,), data_types=("F32",), byte_orders=("ABCD",))
        by_address = {item.requested_address: item for item in rows}
        self.assertTrue(math.isnan(by_address[0].value))
        self.assertEqual(by_address[0].score, 0)
        self.assertIn("Non-finite", " ".join(by_address[0].reasons))
        self.assertIn("Subnormal", " ".join(by_address[2].reasons))
        self.assertIn("above 1e12", " ".join(by_address[4].reasons))
        self.assertIn("0x0000", " ".join(by_address[6].reasons))
        self.assertIn("0xFFFF", " ".join(by_address[8].reasons))
        sentinel = analyze_registers(capture, [8], offsets=(0,), data_types=("S32",), byte_orders=("ABCD",))[0]
        self.assertIn("0xFFFF", " ".join(sentinel.reasons))
        self.assertEqual(sentinel.value, -1)
        self.assertTrue(all(item.in_range is None for item in rows))

    def test_full_pdu_range_iterator_handles_sparse_capture(self):
        candidates = iter_register_candidates({0: 1, 65535: 2}, range(65536), offsets=(0,), data_types=("U16",))
        self.assertEqual([(item.pdu_address, item.value) for item in candidates], [(0, 1), (65535, 2)])

    def test_invalid_capture_configuration_and_addresses_are_rejected(self):
        cases = [
            ({0: -1}, [0], {}), ({0: 65536}, [0], {}), ({-1: 5}, [0], {}),
            ({0: True}, [0], {}), ({0: 1}, [-1], {}), ({0: 1}, [65536], {}),
            ({0: 1}, [0], {"min_value": 5, "max_value": 4}),
            ({0: 1}, [0], {"min_value": float("nan")}),
            ({0: 1}, [0], {"offsets": (0.5,)}),
            ({0: 1}, [0], {"byte_orders": ("bogus",)}),
            ({0: 1}, [0], {"data_types": ("F64",)}),
        ]
        for capture, addresses, options in cases:
            with self.subTest(capture=capture, addresses=addresses, options=options):
                with self.assertRaises(ValueError):
                    analyze_registers(capture, addresses, **options)


if __name__ == "__main__":
    unittest.main()
