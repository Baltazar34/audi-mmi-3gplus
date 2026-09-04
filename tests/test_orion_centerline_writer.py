import json
import math
from pathlib import Path
import sys
import tempfile
import unittest


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from orion_centerline_writer import (
    build_centerline_chunk,
    direction_to_orion,
    read_centerline_sources,
)
from orion_psd_reference_profile import parse_exact_column_table, parse_logical_schema


class OrionCenterlineWriterTests(unittest.TestCase):
    def test_direction_uses_unsigned_full_circle_u16(self) -> None:
        self.assertEqual(direction_to_orion(0.0), 0)
        self.assertEqual(direction_to_orion(math.pi / 2.0), 16384)
        self.assertEqual(direction_to_orion(-math.pi / 2.0), 49152)
        self.assertEqual(direction_to_orion(math.tau), 0)

    def test_reader_rejects_disconnected_segments(self) -> None:
        record = {
            "edge_id": 10,
            "segments": [
                {
                    "index": 0,
                    "start_mercator": [0, 0],
                    "end_mercator": [1, 0],
                    "heading_radians": 0.0,
                    "start_curvature": 0.0,
                    "curvature_rate": 0.0,
                },
                {
                    "index": 1,
                    "start_mercator": [2, 0],
                    "end_mercator": [3, 0],
                    "heading_radians": 0.0,
                    "start_curvature": 0.0,
                    "curvature_rate": 0.0,
                },
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "centerlines.jsonl"
            source.write_text(json.dumps(record) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "disconnected"):
                read_centerline_sources(source)

    def test_chunk_preserves_each_segment_as_straight_part(self) -> None:
        rows = [
            {
                "source_edge_id": 10,
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
                "source_edge_id": 11,
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
        chunk, output_rows, details = build_centerline_chunk(rows)
        schema = parse_logical_schema(chunk)
        self.assertIsNotNone(schema)
        assert schema is not None
        self.assertIsNotNone(parse_exact_column_table(chunk, schema))
        self.assertEqual(details["part_count"], 3)
        self.assertEqual(details["point_lld_count"], 6)
        self.assertEqual(details["clothoid_handle_range"], [1, 2])
        self.assertEqual(details["edge_handle_range"], [3, 4])
        self.assertEqual([row["part_count"] for row in output_rows], [1, 2])
        self.assertTrue(all(details["checks"].values()))


if __name__ == "__main__":
    unittest.main()
