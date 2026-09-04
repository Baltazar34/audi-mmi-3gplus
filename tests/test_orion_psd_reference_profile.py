import struct
import sys
from pathlib import Path
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_psd_reference_profile import (
    candidate_serialized_member_part_count,
    candidate_schema_serialized_part_count,
    class_object_ranges,
    group_serialized_parts,
    parse_catalog,
    parse_column_table,
    parse_exact_column_table,
    parse_logical_schema,
    serialize_exact_column_table,
    serialize_logical_schema,
    schema_member_part_counts,
)


class OrionPsdReferenceProfileTests(unittest.TestCase):
    def test_edge_attributes_is_implicit_and_node_geometry_is_direct(self) -> None:
        schema = {
            "map_name": "Map",
            "composites": [
                {
                    "index": 0,
                    "kind": 2,
                    "name": "Attributes",
                    "row_count": 3,
                    "members": [],
                },
                {
                    "index": 1,
                    "kind": 1,
                    "name": "PointGeometry",
                    "row_count": 3,
                    "members": [],
                },
                {
                    "index": 2,
                    "kind": 1,
                    "name": "EdgeRoadElement",
                    "row_count": 3,
                    "members": [
                        {
                            "index": 0,
                            "kind": 1,
                            "name": "Attributes",
                            "type_code": 0xC0,
                            "type_composite_index": 0,
                            "optional_flag": 0,
                        }
                    ],
                },
                {
                    "index": 3,
                    "kind": 1,
                    "name": "NodeRoadElement",
                    "row_count": 3,
                    "members": [
                        {
                            "index": 0,
                            "kind": 1,
                            "name": "PointGeometry",
                            "type_code": 0xB0,
                            "type_composite_index": 1,
                            "optional_flag": 0,
                        },
                        {
                            "index": 1,
                            "kind": 1,
                            "name": "Vias",
                            "type_code": 0xB0,
                            "type_composite_index": 2,
                            "optional_flag": 1,
                        },
                    ],
                },
            ],
        }
        self.assertEqual(
            schema_member_part_counts(schema),
            {(2, 0): 0, (3, 0): 1, (3, 1): 3},
        )
        groups = group_serialized_parts(
            schema,
            [
                {"tag": 2, "type_code": 0x22, "size": 2},
                {"tag": 2, "type_code": 0x22, "size": 2},
                {"tag": 2, "type_code": 0x24, "size": 6},
                {"tag": 1, "type_code": 0x25, "size": 4},
            ],
        )
        self.assertEqual(groups[0]["parts"], [])
        self.assertEqual(groups[1]["member_name"], "PointGeometry")
        self.assertEqual(groups[1]["part_count"], 1)
        self.assertEqual(groups[2]["part_count"], 3)

    def test_class_object_ranges_skip_structures_and_reserve_zero(self) -> None:
        schema = {
            "composites": [
                {"index": 0, "kind": 2, "row_count": 100},
                {"index": 1, "kind": 1, "row_count": 3},
                {"index": 2, "kind": 3, "row_count": 50},
                {"index": 3, "kind": 1, "row_count": 2},
            ]
        }
        self.assertEqual(class_object_ranges(schema), {1: (1, 3), 3: (4, 5)})

    def test_candidate_member_part_count_handles_special_and_optional_types(self) -> None:
        self.assertEqual(
            candidate_serialized_member_part_count(
                {"kind": 1, "type_code": 0x35, "optional_flag": 1}
            ),
            1,
        )
        self.assertEqual(
            candidate_serialized_member_part_count(
                {"kind": 1, "type_code": 0x90, "optional_flag": 0}
            ),
            2,
        )

    def test_candidate_schema_count_handles_array_and_shared_class_90_part(self) -> None:
        schema = {
            "composites": [
                {
                    "kind": 3,
                    "members": [
                        {"kind": 1, "type_code": 0xB0, "optional_flag": 1}
                    ],
                },
                {
                    "kind": 1,
                    "members": [
                        {"kind": 1, "type_code": 0x90, "optional_flag": 0}
                    ],
                },
                {
                    "kind": 2,
                    "members": [
                        {"kind": 1, "type_code": 0x90, "optional_flag": 0}
                    ],
                },
            ]
        }
        self.assertEqual(candidate_schema_serialized_part_count(schema), 6)

    def test_serialized_parts_are_grouped_by_composite_and_member(self) -> None:
        schema = {
            "composites": [
                {
                    "index": 0,
                    "kind": 3,
                    "name": "ArrayValues",
                    "members": [
                        {
                            "index": 0,
                            "kind": 1,
                            "name": "Values",
                            "type_code": 0xB0,
                            "optional_flag": 1,
                        }
                    ],
                }
            ]
        }
        descriptors = [
            {"tag": 1, "type_code": 0x25, "size": 4},
            {"tag": 2, "type_code": 0x25, "size": 8},
            {"tag": 2, "type_code": 0x23, "size": 2},
        ]
        groups = group_serialized_parts(schema, descriptors)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["part_start"], 0)
        self.assertEqual(groups[0]["part_count"], 3)

    def test_vid_table_optional_scalars_have_mask_and_value_parts(self) -> None:
        schema = {
            "map_name": "VidTable",
            "composites": [
                {
                    "index": 0,
                    "kind": 1,
                    "name": "VidTable",
                    "members": [
                        {
                            "index": 0,
                            "kind": 1,
                            "name": "XacVectorOffsets",
                            "type_code": 0x24,
                            "optional_flag": 1,
                        },
                        {
                            "index": 1,
                            "kind": 1,
                            "name": "AtlasIds",
                            "type_code": 0x26,
                            "optional_flag": 1,
                        },
                    ],
                }
            ],
        }
        self.assertEqual(candidate_schema_serialized_part_count(schema), 4)
        self.assertEqual(
            candidate_serialized_member_part_count(
                {"kind": 1, "type_code": 0xB0, "optional_flag": 1}
            ),
            2,
        )
    def test_catalog_records_and_column_descriptor(self) -> None:
        data = (
            b"\x01\x0cAdasProperty"
            + struct.pack("<HIB", 11, 2, 1)
            + b"\x02\x08PointLlh"
            + struct.pack("<IB", 383, 3)
            + b"\x02\x35"
            + struct.pack("<I", 1532)
            + b"\x01"
        )
        records, columns = parse_catalog(data)
        self.assertEqual(
            records,
            [
                {
                    "offset": 0,
                    "tag": 1,
                    "name": "AdasProperty",
                    "reference": 11,
                    "count": 2,
                    "code": 1,
                },
                {
                    "offset": 21,
                    "tag": 2,
                    "name": "PointLlh",
                    "reference": None,
                    "count": 383,
                    "code": 3,
                },
            ],
        )
        self.assertEqual(columns, [(0x35, 1532)])

    def test_exact_column_table_and_compression_codes(self) -> None:
        prefix = b"schema"
        descriptors = (
            b"\x02\x35" + struct.pack("<I", 1532) + b"\x01"
            + b"\x02\x35" + struct.pack("<I", 1532) + b"\x01"
            + b"\x01\x24" + struct.pack("<I", 766) + b"\x01"
        )
        table = parse_column_table(prefix + descriptors + b"\x01\x02\x03payload")
        self.assertIsNotNone(table)
        assert table is not None
        self.assertEqual(table["offset"], len(prefix))
        self.assertEqual(table["compression_codes"], [1, 2, 3])
        self.assertEqual(table["data_offset"], len(prefix) + len(descriptors) + 3)
        self.assertEqual(
            [item["type_code"] for item in table["descriptors"]],
            [0x35, 0x35, 0x24],
        )

    def test_navcore_logical_schema_drives_exact_column_offsets(self) -> None:
        map_name = b"Map"
        composite = b"\x02\x05Point" + struct.pack("<IB", 2, 1)
        member = b"\x01\x01X\x00\x35\x00"
        prefix_size = 1 + len(map_name) + 20 + 2 + len(composite) + len(member)
        data_offset = prefix_size + 8
        header = struct.pack("<5I", data_offset, 8, 0, 0, 0)
        descriptor = b"\x02\x35" + struct.pack("<I", 8) + b"\x01"
        data = (
            bytes([len(map_name)]) + map_name + header + struct.pack("<H", 1)
            + composite + member + descriptor + b"\x01" + b"payload!"
        )
        schema = parse_logical_schema(data)
        self.assertIsNotNone(schema)
        assert schema is not None
        self.assertEqual(schema["schema_end"], prefix_size)
        self.assertEqual(schema["composites"][0]["members"][0]["name"], "X")
        table = parse_exact_column_table(data, schema)
        self.assertIsNotNone(table)
        assert table is not None
        self.assertEqual(table["data_offset"], data_offset)
        self.assertEqual(table["compression_codes"], [1])
        self.assertEqual(serialize_logical_schema(schema), data[:prefix_size])
        self.assertEqual(
            serialize_exact_column_table(table), data[prefix_size:data_offset]
        )

    def test_indirect_kind3_part_has_twelve_byte_descriptor(self) -> None:
        schema = {"schema_end": 0, "data_offset": 13}
        descriptor = (
            b"\x03\x35\x03" + struct.pack("<II", 5, 20) + b"\x01"
        )
        table = parse_exact_column_table(descriptor + b"\x01" + b"X" * 20, schema)
        self.assertIsNotNone(table)
        assert table is not None
        self.assertEqual(table["descriptor_end"], 12)
        self.assertEqual(table["compression_codes"], [1])
        self.assertEqual(table["descriptors"][0]["member_index"], 3)
        self.assertEqual(table["descriptors"][0]["indirect_count"], 5)
        self.assertEqual(table["descriptors"][0]["size"], 20)


if __name__ == "__main__":
    unittest.main()
