from __future__ import annotations

import struct
import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_xac_vector_bind import parse_fldb_directory, subsequence_bounds  # noqa: E402


class OrionXacVectorBindTests(unittest.TestCase):
    def test_fldb_directory_parser(self) -> None:
        data = bytearray(256)
        struct.pack_into("<I", data, 0, 64)
        struct.pack_into("<I", data, 12, 2)
        struct.pack_into("<I", data, 16, 36)
        data[20:24] = b"FLDB"
        directory = 72
        data[directory : directory + 5] = b"a.xac"
        struct.pack_into("<III", data, directory + 24, 0x12345678, 160, 20)
        second = directory + 36
        data[second : second + 5] = b"b.xac"
        struct.pack_into("<III", data, second + 24, 0xABCDEF00, 180, 30)
        entries = parse_fldb_directory(data, len(data))
        self.assertEqual([row["name"] for row in entries], ["a.xac", "b.xac"])
        self.assertEqual(entries[1]["offset"], 180)
        self.assertEqual(entries[1]["size"], 30)

    def test_subsequence_bounds_identify_forced_and_ambiguous_matches(self) -> None:
        earliest, latest = subsequence_bounds([2, 3, 4], [1, 2, 9, 3, 3, 4, 8])
        self.assertEqual(earliest, [1, 3, 5])
        self.assertEqual(latest, [1, 4, 5])
        self.assertEqual(
            [left == right for left, right in zip(earliest, latest)],
            [True, False, True],
        )

    def test_missing_subsequence_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "not an XAC vector subsequence"):
            subsequence_bounds([2, 4], [2, 3])


if __name__ == "__main__":
    unittest.main()
