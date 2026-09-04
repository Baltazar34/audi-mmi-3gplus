from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_edge_property_decode import decode_property_fields


class OrionEdgePropertyDecodeTests(unittest.TestCase):
    def test_indirect_property_dictionary_is_expanded(self) -> None:
        subclasses = [
            {
                "index": 2,
                "name": "AdasProperty",
                "row_count": 1,
                "members": [{"index": 0, "kind": 1, "name": "Compliant", "type_code": 0x10}],
            },
            {
                "index": 3,
                "name": "AudiUrbanProperty",
                "row_count": 1,
                "members": [{"index": 0, "kind": 1, "name": "Urban", "type_code": 0x10}],
            },
            {
                "index": 4,
                "name": "PassingRestrictionProperty",
                "row_count": 3,
                "members": [
                    {"index": 0, "kind": 1, "name": "VehicleType", "type_code": 0x24},
                    {"index": 1, "kind": 2, "name": None, "type_code": 0x23},
                ],
            },
            {
                "index": 5,
                "name": "UrbanProperty",
                "row_count": 1,
                "members": [{"index": 0, "kind": 1, "name": "Urban", "type_code": 0x10}],
            },
        ]
        schema = {"composites": subclasses}
        descriptors = [
            {"tag": 1, "type_code": 0x10, "size": 1},
            {"tag": 1, "type_code": 0x10, "size": 1},
            {
                "tag": 3,
                "type_code": 0x24,
                "size": 4,
                "member_index": 1,
                "indirect_count": 2,
            },
            {"tag": 2, "type_code": 0x23, "size": 3},
            {"tag": 1, "type_code": 0x10, "size": 1},
        ]
        payloads = [b"\x01", b"\x00", b"\x01\x00\xe7\x0d", b"\x00\x01\x01", b"\x01"]
        decoded = b"".join(payloads)
        layouts = []
        cursor = 0
        for payload in payloads:
            layouts.append(SimpleNamespace(payload_offset=cursor, payload_size=len(payload)))
            cursor += len(payload)
        fields, report = decode_property_fields(
            decoded,
            schema,
            {"descriptors": descriptors},
            [],
            layouts,
            subclasses,
            {"AdasProperty": 0, "AudiUrbanProperty": 1, "UrbanProperty": 4},
            {},
        )
        self.assertEqual(
            [row["VehicleType"] for row in fields["PassingRestrictionProperty"]],
            [1, 3559, 3559],
        )
        vehicle = next(
            row for row in report["members"] if row["member"] == "VehicleType"
        )
        self.assertEqual(vehicle["decoding"], "indirect_dictionary")
        self.assertEqual(vehicle["index_descriptor"], 3)


if __name__ == "__main__":
    unittest.main()
