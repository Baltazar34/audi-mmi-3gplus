from __future__ import annotations

import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_psd_reference_profile import parse_exact_column_table, parse_logical_schema  # noqa: E402
from orion_vidtable_row_mapping import decode_vidtable_rows  # noqa: E402


class OrionVidTableRowMappingTests(unittest.TestCase):
    def decode_sample(self, index: int):
        root = Path(__file__).resolve().parents[1] / "out" / "orion_vidtable_schema_sample"
        decoded = (root / f"sample_{index:02d}.decoded.bin").read_bytes()
        schema = parse_logical_schema(decoded)
        assert schema is not None
        table = parse_exact_column_table(decoded, schema)
        assert table is not None
        return decode_vidtable_rows(decoded, schema, table)

    def test_direct_rows_are_parallel(self) -> None:
        atlas_ids, offsets, profile = self.decode_sample(1)
        self.assertEqual(profile["variant"], "direct")
        self.assertEqual(len(atlas_ids), 59)
        self.assertEqual(len(offsets), 59)
        self.assertEqual(profile["dictionary_count"], 59)

    def test_indirect_dictionary_indices_expand_exactly(self) -> None:
        atlas_ids, offsets, profile = self.decode_sample(0)
        self.assertEqual(profile["variant"], "indirect")
        self.assertEqual(len(atlas_ids), 3789)
        self.assertEqual(len(offsets), 3789)
        self.assertEqual(profile["dictionary_count"], 470)
        self.assertEqual((profile["index_min"], profile["index_max"]), (0, 469))


if __name__ == "__main__":
    unittest.main()
