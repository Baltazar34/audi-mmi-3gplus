from __future__ import annotations

import struct
from pathlib import Path
import sys
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "tools"))

from basic_handle2_directory import (  # noqa: E402
    _record_header,
    decode_edge_directory,
    decode_record_data_end,
)
from psf_decode import PsfError


class BasicHandle2DirectoryTests(unittest.TestCase):
    def test_nonzero_auxiliary_count_uses_count_plus_one_u32_values(self) -> None:
        payload = bytearray(96)
        struct.pack_into("<H", payload, 6, 1)
        struct.pack_into("<2I", payload, 8, 0x11223344, 0x55667788)
        struct.pack_into("<2H", payload, 16, 40, 64)
        payload[40] = 0x05
        payload[64] = 0

        decoded = decode_edge_directory(bytes(payload), 2)

        self.assertEqual(decoded.auxiliary_count, 1)
        self.assertEqual(decoded.auxiliary_entries, (0x11223344,))
        self.assertEqual(decoded.auxiliary_trailer, 0x55667788)
        self.assertEqual(decoded.directory_base, 16)
        self.assertEqual(decoded.directory_end, 20)
        self.assertEqual(decoded.record_offsets, (40, 64))

    def test_zero_auxiliary_count_puts_directory_at_offset_eight(self) -> None:
        payload = bytearray(32)
        struct.pack_into("<H", payload, 6, 0)
        struct.pack_into("<H", payload, 8, 20)
        decoded = decode_edge_directory(bytes(payload), 1)
        self.assertEqual(decoded.auxiliary_entries, ())
        self.assertIsNone(decoded.auxiliary_trailer)
        self.assertEqual(decoded.directory_base, 8)
        self.assertEqual(decoded.record_offsets, (20,))

    def test_record_pointer_before_directory_end_is_rejected(self) -> None:
        payload = bytearray(32)
        struct.pack_into("<H", payload, 6, 0)
        struct.pack_into("<H", payload, 8, 9)
        with self.assertRaises(PsfError):
            decode_edge_directory(bytes(payload), 1)

    def test_u16_at_one_bounds_record_data_before_footer(self) -> None:
        payload = bytearray(40)
        struct.pack_into("<H", payload, 1, 33)
        self.assertEqual(decode_record_data_end(bytes(payload), 20), 33)
        with self.assertRaises(PsfError):
            decode_record_data_end(bytes(payload), 33)

    def test_base_three_record_header_tracks_flag_selected_pointers(self) -> None:
        payload = bytearray(96)
        payload[40] = 0x05
        payload[41:43] = b"\xaa\xbb"
        struct.pack_into("<2H", payload, 43, 12, 24)
        payload[47] = 3
        payload[52] = 7
        payload[64] = 9

        header = _record_header(bytes(payload), 40, 3)

        self.assertTrue(header["header_fits"])
        self.assertEqual(header["pointer_bits"], (0, 2))
        self.assertEqual(header["main_count"], 3)
        pointers = header["pointers"]
        self.assertEqual([pointer["absolute_offset"] for pointer in pointers], [52, 64])
        self.assertTrue(all(pointer["after_header"] for pointer in pointers))


if __name__ == "__main__":
    unittest.main()
