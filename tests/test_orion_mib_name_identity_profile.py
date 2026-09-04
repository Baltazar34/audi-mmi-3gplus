from __future__ import annotations

import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_mib_name_identity_profile import set_relation  # noqa: E402


class OrionMibNameIdentityProfileTests(unittest.TestCase):
    def test_set_relation(self) -> None:
        self.assertEqual(set_relation(set(), {"a"}), "missing")
        self.assertEqual(set_relation({"a"}, {"a"}), "equal")
        self.assertEqual(set_relation({"a", "b"}, {"b", "c"}), "overlap")
        self.assertEqual(set_relation({"a"}, {"b"}), "disjoint")


if __name__ == "__main__":
    unittest.main()
