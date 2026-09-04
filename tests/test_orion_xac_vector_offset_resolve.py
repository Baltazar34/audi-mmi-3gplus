from __future__ import annotations

import struct
import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_xac_vector_offset_resolve import (  # noqa: E402
    apply_proven_owner_invariant,
    resolve_vector_offset,
    vector_header,
)


class OrionXacVectorOffsetResolveTests(unittest.TestCase):
    def test_version_four_uses_direct_offset(self) -> None:
        data = bytearray(140)
        struct.pack_into(">H", data, 20, 4)
        data[132] = 0xC0
        header = vector_header(data, 0, len(data))
        self.assertEqual(header["mode"], "direct")
        self.assertEqual(resolve_vector_offset(data, 0, len(data), header, 132), 132)

    def test_version_five_indexed_offset_uses_be16_word_table(self) -> None:
        data = bytearray(512)
        struct.pack_into(">H", data, 20, 5)
        struct.pack_into(">I", data, 108, 300)
        struct.pack_into(">H", data, 112, 4)
        struct.pack_into(">H", data, 114, 1)
        struct.pack_into(">HHHH", data, 300, 70, 84, 91, 100)
        data[182] = 0xC0
        header = vector_header(data, 0, len(data))
        self.assertEqual(header["mode"], "indexed")
        self.assertEqual(resolve_vector_offset(data, 0, len(data), header, 4), 182)

    def test_indexed_offset_must_be_even_and_in_range(self) -> None:
        data = bytearray(256)
        struct.pack_into(">H", data, 20, 5)
        struct.pack_into(">I", data, 108, 200)
        struct.pack_into(">H", data, 112, 2)
        struct.pack_into(">H", data, 114, 1)
        header = vector_header(data, 0, len(data))
        with self.assertRaisesRegex(ValueError, "not even"):
            resolve_vector_offset(data, 0, len(data), header, 1)
        with self.assertRaisesRegex(ValueError, "exceeds index table"):
            resolve_vector_offset(data, 0, len(data), header, 4)

    def test_owner_invariant_must_be_proven_by_unique_bindings(self) -> None:
        rows = [
            {"candidate_profiles": [{"owner_name": "tile_2.xac"}]},
            {
                "candidate_profiles": [
                    {"owner_name": "other_1.xac"},
                    {"owner_name": "other_2.xac"},
                ]
            },
        ]
        suffix, support = apply_proven_owner_invariant(rows)
        self.assertEqual((suffix, support), ("_2.xac", 1))
        self.assertEqual(
            [row["owner_name"] for row in rows[1]["candidate_profiles"]],
            ["other_2.xac"],
        )


if __name__ == "__main__":
    unittest.main()
