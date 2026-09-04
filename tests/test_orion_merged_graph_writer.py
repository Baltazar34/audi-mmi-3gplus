import math
from pathlib import Path
import sys
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_merged_graph_writer import build_merged_graph_chunk
from orion_psd_reference_profile import parse_exact_column_table, parse_logical_schema


class OrionMergedGraphWriterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.nodes = [
            {"source_id": 10, "longitude": 1, "latitude": 2, "height": 0},
            {"source_id": 11, "longitude": 3, "latitude": 4, "height": 0},
            {"source_id": 12, "longitude": 5, "latitude": 6, "height": 0},
        ]
        self.edges = [
            {
                "source_edge_id": 20,
                "from_source_node_id": 10,
                "to_source_node_id": 12,
                "geometry_parts": [{"secondary_flags": 0x20}],
            },
            {
                "source_edge_id": 21,
                "from_source_node_id": 99,
                "to_source_node_id": 11,
            },
        ]
        self.centerlines = [
            {
                "source_edge_id": 20,
                "segments": [
                    {
                        "index": 0,
                        "start_mercator": (0, 0),
                        "end_mercator": (100, 0),
                        "heading_radians": 0.0,
                    }
                ],
            },
            {
                "source_edge_id": 21,
                "segments": [
                    {
                        "index": 0,
                        "start_mercator": (0, 0),
                        "end_mercator": (0, 100),
                        "heading_radians": math.pi / 2.0,
                    },
                    {
                        "index": 1,
                        "start_mercator": (0, 100),
                        "end_mercator": (100, 100),
                        "heading_radians": 0.0,
                    },
                ],
            },
        ]

    def test_all_graph_layers_share_one_handle_space(self) -> None:
        chunk, node_rows, edge_rows, details = build_merged_graph_chunk(
            self.nodes, self.edges, self.centerlines
        )
        schema = parse_logical_schema(chunk)
        self.assertIsNotNone(schema)
        assert schema is not None
        self.assertIsNotNone(parse_exact_column_table(chunk, schema))
        self.assertEqual(details["adas_property_handle_range"], [1, 1])
        self.assertEqual(details["audi_urban_property_handle_range"], [2, 2])
        self.assertEqual(details["urban_property_handle_range"], [3, 4])
        self.assertEqual(details["point_geometry_handle_range"], [5, 7])
        self.assertEqual(details["clothoid_handle_range"], [8, 9])
        self.assertEqual(details["edge_handle_range"], [10, 11])
        self.assertEqual(details["node_handle_range"], [12, 14])
        self.assertEqual(details["property_handle_count"], 6)
        self.assertEqual(details["urban_edge_count"], 1)
        self.assertEqual(details["centerline_part_count"], 3)
        self.assertEqual(details["point_lld_count"], 6)
        self.assertEqual(
            [row["centerline_handle"] for row in edge_rows], [8, 9]
        )
        self.assertEqual(
            [(row["from_handle"], row["to_handle"]) for row in edge_rows],
            [(12, 14), (0, 13)],
        )
        self.assertEqual(
            [row["via_edge_handles"] for row in node_rows], [[10], [11], [10]]
        )
        self.assertTrue(all(details["checks"].values()))

    def test_edge_and_centerline_ids_must_match_in_order(self) -> None:
        reversed_centerlines = list(reversed(self.centerlines))
        with self.assertRaisesRegex(ValueError, "order or IDs differ"):
            build_merged_graph_chunk(
                self.nodes, self.edges, reversed_centerlines
            )


if __name__ == "__main__":
    unittest.main()
