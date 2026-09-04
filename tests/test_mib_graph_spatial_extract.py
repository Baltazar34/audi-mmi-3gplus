from __future__ import annotations

import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from basic_handle2_text_decode import TextEntry  # noqa: E402
from mib_graph_spatial_extract import compact_semantic_names, normalize_name  # noqa: E402


class MibGraphSpatialExtractTests(unittest.TestCase):
    def test_normalize_name_folds_case_diacritics_and_punctuation(self) -> None:
        self.assertEqual(normalize_name("  Bulevar—Džordža VAŠINGTONA "), "bulevar dzordza vasingtona")

    def test_compact_names_preserve_base_and_transliteration(self) -> None:
        base = TextEntry(33, False, ("Улица",), 33, ("",), 0, 0)
        latin = TextEntry(33, True, ("Ulica",), 33, ("",), 0, 0)
        names, normalized = compact_semantic_names((base, latin))
        self.assertEqual(names[0]["base_values"], ["Улица"])
        self.assertEqual(names[0]["transliteration_values"], ["Ulica"])
        self.assertEqual(normalized, ["ulica", "улица"])


if __name__ == "__main__":
    unittest.main()
