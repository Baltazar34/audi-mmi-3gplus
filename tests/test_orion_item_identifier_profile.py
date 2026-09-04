from __future__ import annotations

import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_item_identifier_profile import geometry_relation, metres  # noqa: E402


class OrionItemIdentifierProfileTests(unittest.TestCase):
    def test_geometry_relation_distinguishes_order_and_shape(self) -> None:
        line = [(19.0, 42.0), (19.001, 42.001), (19.002, 42.002)]
        self.assertEqual(geometry_relation(line, list(line)), "exact")
        self.assertEqual(geometry_relation(line, list(reversed(line))), "reversed")
        self.assertEqual(
            geometry_relation(line, [(19.0, 42.0), (19.003, 42.003)]),
            "different",
        )

    def test_endpoint_distance_is_zero_for_same_point(self) -> None:
        self.assertEqual(metres((19.25, 42.44), (19.25, 42.44)), 0.0)


if __name__ == "__main__":
    unittest.main()
