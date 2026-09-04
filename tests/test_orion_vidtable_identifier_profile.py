from __future__ import annotations

import struct
import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_vidtable_identifier_profile import raw_u64_values  # noqa: E402


class OrionVidTableIdentifierProfileTests(unittest.TestCase):
    def test_raw_u64_values_preserves_high_bits(self) -> None:
        values = [0x12345678ABCDEF01, 0xFEDCBA9876543210]
        payload = b"".join(struct.pack("<Q", value) for value in values)
        self.assertEqual(raw_u64_values(payload), values)

    def test_raw_u64_values_rejects_partial_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "64-bit aligned"):
            raw_u64_values(b"\x00" * 7)


if __name__ == "__main__":
    unittest.main()
