import json
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_column_codec import pack_code1_values, unpack_code1_values
from orion_object_writer import (
    build_graph_reference_chunk,
    build_integrated_graph_chunk,
    build_point_llh_chunk,
    coordinate_to_orion,
    read_point_llh_rows,
)
from orion_psd_reference_profile import parse_exact_column_table, parse_logical_schema
from orion_schema_extract import schema_names


class OrionObjectWriterTests(unittest.TestCase):
    def test_integrated_graph_binds_points_edges_nodes_and_vias(self) -> None:
        nodes = [
            {"source_id": 10, "longitude": 1, "latitude": 2, "height": 0},
            {"source_id": 11, "longitude": 3, "latitude": 4, "height": 0},
            {"source_id": 12, "longitude": 5, "latitude": 6, "height": 0},
        ]
        edges = [
            {"source_edge_id": 20, "from_source_node_id": 10, "to_source_node_id": 12},
            {"source_edge_id": 21, "from_source_node_id": 99, "to_source_node_id": 11},
        ]
        chunk, node_rows, edge_rows, details = build_integrated_graph_chunk(
            nodes, edges
        )
        self.assertTrue(chunk)
        self.assertEqual(details["point_geometry_handle_range"], [1, 3])
        self.assertEqual(details["edge_handle_range"], [4, 5])
        self.assertEqual(details["node_handle_range"], [6, 8])
        self.assertEqual(
            [row["via_edge_handles"] for row in node_rows], [[4], [5], [4]]
        )
        self.assertEqual(
            [(row["from_handle"], row["to_handle"]) for row in edge_rows],
            [(6, 8), (0, 7)],
        )
        self.assertTrue(all(details["checks"].values()))

    def test_graph_references_use_global_handles_and_zero_for_absent_nodes(self) -> None:
        nodes = [
            {"source_id": 10, "longitude": 1, "latitude": 2, "height": 0},
            {"source_id": 11, "longitude": 3, "latitude": 4, "height": 0},
            {"source_id": 12, "longitude": 5, "latitude": 6, "height": 0},
        ]
        edges = [
            {"source_edge_id": 20, "from_source_node_id": 10, "to_source_node_id": 12},
            {"source_edge_id": 21, "from_source_node_id": 99, "to_source_node_id": 11},
        ]
        chunk, rows, details = build_graph_reference_chunk(nodes, edges)
        self.assertTrue(chunk)
        self.assertEqual(details["edge_handle_range"], [1, 2])
        self.assertEqual(details["node_handle_range"], [3, 5])
        self.assertEqual(details["physical_type"], "0x22")
        self.assertEqual(
            [(row["from_handle"], row["to_handle"]) for row in rows],
            [(3, 5), (0, 4)],
        )
        self.assertTrue(all(details["checks"].values()))

    def test_schema_name_index_includes_composites_and_named_members(self) -> None:
        schema = {
            "map_name": "Map",
            "composites": [
                {
                    "name": "EdgeRoadElement",
                    "members": [{"name": "From"}, {"name": None}],
                }
            ],
        }
        self.assertEqual(schema_names(schema), {"Map", "EdgeRoadElement", "From"})

    def test_code1_subbyte_values_are_lsb_first_and_roundtrip(self) -> None:
        packed = pack_code1_values(0x21, [0, 1, 2, 3])
        self.assertEqual(packed, b"\xe4")
        self.assertEqual(unpack_code1_values(0x21, packed, 4), [0, 1, 2, 3])

    def test_code1_signed_values_roundtrip(self) -> None:
        values = [-2_000_000_000, -1, 0, 1, 2_000_000_000]
        packed = pack_code1_values(0x35, values)
        self.assertEqual(unpack_code1_values(0x35, packed, len(values)), values)

    def test_point_llh_chunk_builds_and_reparses(self) -> None:
        rows = [
            {"source_id": 1, "longitude": 205_269_354, "latitude": 421_181_087, "height": 0},
            {"source_id": 2, "longitude": 205_286_602, "latitude": 421_187_217, "height": 0},
        ]
        chunk, details = build_point_llh_chunk(rows)
        schema = parse_logical_schema(chunk)
        self.assertIsNotNone(schema)
        assert schema is not None
        table = parse_exact_column_table(chunk, schema)
        self.assertIsNotNone(table)
        self.assertEqual(schema["map_name"], "Map")
        self.assertEqual(schema["composites"][0]["name"], "PointLlh")
        self.assertEqual(schema["composites"][0]["row_count"], 2)
        self.assertTrue(all(details["checks"].values()))

    def test_jsonl_source_conversion_is_deterministic(self) -> None:
        record = {
            "node_id": 7,
            "coordinate": {"wgs84": [20.52693545, 42.11810865]},
        }
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "nodes.jsonl"
            source.write_text(json.dumps(record) + "\n", encoding="utf-8")
            rows = read_point_llh_rows(source)
        self.assertEqual(coordinate_to_orion("-1.00000005"), -10_000_001)
        self.assertEqual(
            rows,
            [{"source_id": 7, "longitude": 205_269_355, "latitude": 421_181_087, "height": 0}],
        )


if __name__ == "__main__":
    unittest.main()
