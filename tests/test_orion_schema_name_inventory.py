from __future__ import annotations

import struct
import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_schema_name_inventory import parse_legacy_logical_schema  # noqa: E402


class OrionSchemaNameInventoryTests(unittest.TestCase):
    def test_parses_legacy_schema_without_member_annotations(self) -> None:
        header = b"\x03Map" + struct.pack("<5I", 31, 7, 0, 0, 0) + struct.pack("<H", 1)
        composite = b"\x01\x04Road" + struct.pack("<HI", 0xFFFF, 2) + b"\x01"
        member = b"\x01\x04Name\x24\x00"
        schema = parse_legacy_logical_schema(header + composite + member)
        self.assertIsNotNone(schema)
        assert schema is not None
        self.assertEqual(schema["map_name"], "Map")
        self.assertEqual(schema["schema_variant"], "legacy-no-member-annotations")
        self.assertEqual(schema["composites"][0]["members"][0]["name"], "Name")


if __name__ == "__main__":
    unittest.main()
