#!/usr/bin/env python3
"""Build a self-validating decoded Orion clothoid centerline graph chunk.

Each non-zero MIB polyline leg becomes one two-position
ClothoidCenterlineGeometryPart.  Both endpoint directions equal the leg
heading, so the encoded part is the zero-curvature special case and preserves
the source segment without inventing tangent continuity at polyline corners.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Iterable

from orion_column_codec import (
    assemble_code1_payload,
    pack_code1_values,
    unpack_code1_values,
    validate_code1_payload_roundtrip,
)
from orion_object_writer import (
    POINT_TYPE,
    _class_composite,
    _reference_member,
    _smallest_unsigned_type,
    coordinate_to_orion,
)
from orion_psd_reference_profile import (
    class_object_ranges,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
    serialize_exact_column_table,
    serialize_logical_schema,
)
from psf_decode import _mercator_to_wgs84


SCHEMA_VERSION = 1
DIRECTION_TYPE = 0x24
DIRECTION_STEPS = 1 << 16


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-centerline-writer stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def direction_to_orion(heading_radians: float) -> int:
    """Convert mathematical radians to an unsigned Orion full-circle u16."""

    if not math.isfinite(heading_radians):
        raise ValueError("direction must be finite")
    normalized = heading_radians % math.tau
    return int(round(normalized * DIRECTION_STEPS / math.tau)) % DIRECTION_STEPS


def read_centerline_sources(
    source_path: Path, limit: int = 0
) -> list[dict[str, object]]:
    """Read and strictly validate the autonomous clothoid JSONL source."""

    if limit < 0:
        raise ValueError("limit must not be negative")
    rows: list[dict[str, object]] = []
    seen_ids: set[int] = set()
    with source_path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            edge_id = int(record["edge_id"])
            if edge_id in seen_ids:
                raise ValueError(f"line {line_number}: duplicate edge_id {edge_id}")
            seen_ids.add(edge_id)
            raw_segments = record.get("segments")
            if not isinstance(raw_segments, list) or not raw_segments:
                raise ValueError(f"line {line_number}: edge has no clothoid segments")
            segments: list[dict[str, object]] = []
            previous_end: tuple[int, int] | None = None
            for expected_index, raw in enumerate(raw_segments):
                if not isinstance(raw, dict) or int(raw.get("index", -1)) != expected_index:
                    raise ValueError(
                        f"line {line_number}: non-contiguous segment index"
                    )
                start_raw = raw.get("start_mercator")
                end_raw = raw.get("end_mercator")
                if (
                    not isinstance(start_raw, list)
                    or len(start_raw) != 2
                    or not isinstance(end_raw, list)
                    or len(end_raw) != 2
                ):
                    raise ValueError(f"line {line_number}: invalid segment endpoints")
                start = (int(start_raw[0]), int(start_raw[1]))
                end = (int(end_raw[0]), int(end_raw[1]))
                if start == end:
                    raise ValueError(f"line {line_number}: zero-length segment")
                if previous_end is not None and start != previous_end:
                    raise ValueError(f"line {line_number}: disconnected segment chain")
                heading = float(raw["heading_radians"])
                expected_heading = math.atan2(end[1] - start[1], end[0] - start[0])
                angular_error = abs(
                    (heading - expected_heading + math.pi) % math.tau - math.pi
                )
                if angular_error > 1e-12:
                    raise ValueError(f"line {line_number}: heading/endpoints mismatch")
                if float(raw.get("start_curvature", math.nan)) != 0.0 or float(
                    raw.get("curvature_rate", math.nan)
                ) != 0.0:
                    raise ValueError(f"line {line_number}: segment is not zero-curvature")
                segments.append(
                    {
                        "index": expected_index,
                        "start_mercator": start,
                        "end_mercator": end,
                        "heading_radians": heading,
                    }
                )
                previous_end = end
            rows.append({"source_edge_id": edge_id, "segments": segments})
            if limit and len(rows) >= limit:
                break
    if not rows:
        raise ValueError("source contains no centerline rows")
    return rows


def _scalar_member(index: int, name: str, type_code: int) -> dict[str, object]:
    return {
        "index": index,
        "kind": 1,
        "name": name,
        "annotations": [],
        "type_code": type_code,
        "type_composite_index": None,
        "optional_flag": 0,
    }


def _structure_member(
    index: int, name: str, target_composite_index: int
) -> dict[str, object]:
    return {
        "index": index,
        "kind": 1,
        "name": name,
        "annotations": [],
        "type_code": 0xC0,
        "type_composite_index": target_composite_index,
        "optional_flag": 1,
    }


def _centerline_schema(
    edge_count: int,
    part_count: int,
    point_count: int,
    data_offset: int,
    payload_size: int,
) -> dict[str, object]:
    composites = [
        {
            "index": 0,
            "kind": 2,
            "name": "PointLld",
            "base_index": None,
            "row_count": point_count,
            "member_count": 3,
            "members": [
                _scalar_member(0, "Longitude", POINT_TYPE),
                _scalar_member(1, "Latitude", POINT_TYPE),
                _scalar_member(2, "Direction", DIRECTION_TYPE),
            ],
        },
        {
            "index": 1,
            "kind": 2,
            "name": "ClothoidCenterlineGeometryPart",
            "base_index": None,
            "row_count": part_count,
            "member_count": 1,
            "members": [_structure_member(0, "Positions", 0)],
        },
        _class_composite(2, "Geometry", 0xFFFF, 0, []),
        _class_composite(3, "CenterlineGeometry", 2, 0, []),
        _class_composite(
            4,
            "ClothoidCenterlineGeometry",
            3,
            edge_count,
            [_structure_member(0, "Parts", 1)],
        ),
        _class_composite(5, "Item", 0xFFFF, 0, []),
        _class_composite(6, "Atom", 5, 0, []),
        _class_composite(7, "RoadElement", 6, 0, []),
        _class_composite(
            8,
            "EdgeRoadElement",
            7,
            edge_count,
            [_reference_member(0, "CenterlineGeometry", 3)],
        ),
    ]
    return {
        "map_name": "Map",
        "data_offset": data_offset,
        "payload_size": payload_size,
        "header_values": [data_offset, payload_size, 0, 0, 0],
        "composite_count": len(composites),
        "composites": composites,
    }


def _point_lld(x: int, y: int, direction: int) -> dict[str, int]:
    longitude, latitude = _mercator_to_wgs84(x, y)
    return {
        "longitude": coordinate_to_orion(longitude),
        "latitude": coordinate_to_orion(latitude),
        "direction": direction,
    }


def build_centerline_chunk(
    centerlines: Iterable[dict[str, object]],
) -> tuple[bytes, list[dict[str, object]], dict[str, object]]:
    """Encode PointLld, clothoid parts and Edge centerline handles."""

    rows = list(centerlines)
    if not rows:
        raise ValueError("at least one centerline is required")
    parts: list[list[dict[str, int]]] = []
    output_rows: list[dict[str, object]] = []
    part_counts: list[int] = []
    for row in rows:
        raw_segments = row["segments"]
        if not isinstance(raw_segments, list) or not raw_segments:
            raise ValueError("centerline row has no segments")
        first_part = len(parts)
        for raw in raw_segments:
            if not isinstance(raw, dict):
                raise ValueError("invalid normalized segment")
            direction = direction_to_orion(float(raw["heading_radians"]))
            start = raw["start_mercator"]
            end = raw["end_mercator"]
            if not isinstance(start, tuple) or not isinstance(end, tuple):
                raise ValueError("normalized segment endpoints must be tuples")
            parts.append(
                [
                    _point_lld(int(start[0]), int(start[1]), direction),
                    _point_lld(int(end[0]), int(end[1]), direction),
                ]
            )
        part_counts.append(len(raw_segments))
        output_rows.append(
            {
                "source_edge_id": int(row["source_edge_id"]),
                "first_part_row": first_part,
                "part_count": len(raw_segments),
                "point_lld_count": 2 * len(raw_segments),
            }
        )

    flat_points = [point for part in parts for point in part]
    provisional = _centerline_schema(
        len(rows), len(parts), len(flat_points), 1, 1
    )
    ranges = class_object_ranges(provisional)
    clothoid_range = ranges[4]
    edge_range = ranges[8]
    for index, row in enumerate(output_rows):
        row["centerline_handle"] = clothoid_range[0] + index
        row["edge_handle"] = edge_range[0] + index

    columns = [
        [point["longitude"] for point in flat_points],
        [point["latitude"] for point in flat_points],
        [point["direction"] for point in flat_points],
        [2] * len(parts),
        part_counts,
        [int(row["centerline_handle"]) for row in output_rows],
    ]
    part_position_type = _smallest_unsigned_type(2)
    part_count_type = _smallest_unsigned_type(max(part_counts))
    centerline_reference_type = _smallest_unsigned_type(clothoid_range[1])
    physical_types = [
        POINT_TYPE,
        POINT_TYPE,
        DIRECTION_TYPE,
        part_position_type,
        part_count_type,
        centerline_reference_type,
    ]
    payloads = [
        pack_code1_values(type_code, values)
        for type_code, values in zip(physical_types, columns)
    ]
    descriptors = [
        {"tag": 2, "type_code": type_code, "size": len(payload)}
        for type_code, payload in zip(physical_types, payloads)
    ]
    table = {
        "descriptors": descriptors,
        "compression_codes": [1] * len(descriptors),
    }
    table_bytes = serialize_exact_column_table(table)
    payload = assemble_code1_payload(descriptors, payloads)
    provisional = _centerline_schema(
        len(rows), len(parts), len(flat_points), 1, len(payload)
    )
    schema_size = len(serialize_logical_schema(provisional))
    data_offset = schema_size + len(table_bytes)
    schema_bytes = serialize_logical_schema(
        _centerline_schema(
            len(rows), len(parts), len(flat_points), data_offset, len(payload)
        )
    )
    chunk = schema_bytes + table_bytes + payload

    parsed_schema = parse_logical_schema(chunk)
    if parsed_schema is None:
        raise ValueError("centerline schema cannot be reparsed")
    parsed_table = parse_exact_column_table(chunk, parsed_schema)
    if parsed_table is None:
        raise ValueError("centerline table cannot be reparsed")
    groups = group_serialized_parts(parsed_schema, parsed_table["descriptors"])
    layouts = validate_code1_payload_roundtrip(
        chunk,
        int(parsed_schema["data_offset"]),
        parsed_table["descriptors"],
        parsed_table["compression_codes"],
    )
    decoded_columns = [
        unpack_code1_values(
            type_code,
            chunk[layout.payload_offset : layout.payload_offset + layout.payload_size],
            len(values),
        )
        for type_code, values, layout in zip(physical_types, columns, layouts)
    ]
    grouped = {
        (group["composite_name"], group["member_name"]): group["part_count"]
        for group in groups
    }
    centerline_values = decoded_columns[5]
    checks = {
        "schema_byte_identical": serialize_logical_schema(parsed_schema)
        == schema_bytes,
        "column_table_byte_identical": serialize_exact_column_table(parsed_table)
        == table_bytes,
        "whole_chunk_byte_identical": (
            serialize_logical_schema(parsed_schema)
            + serialize_exact_column_table(parsed_table)
            + chunk[int(parsed_schema["data_offset"]) :]
            == chunk
        ),
        "class_handle_ranges_identical": class_object_ranges(parsed_schema)
        == ranges,
        "logical_members_grouped": grouped
        == {
            ("PointLld", "Longitude"): 1,
            ("PointLld", "Latitude"): 1,
            ("PointLld", "Direction"): 1,
            ("ClothoidCenterlineGeometryPart", "Positions"): 1,
            ("ClothoidCenterlineGeometry", "Parts"): 1,
            ("EdgeRoadElement", "CenterlineGeometry"): 1,
        },
        "code1_values_identical": decoded_columns == columns,
        "every_part_has_two_positions": decoded_columns[3] == [2] * len(parts),
        "part_cardinalities_match": decoded_columns[4] == part_counts
        and sum(decoded_columns[4]) == len(parts),
        "every_edge_targets_own_clothoid": centerline_values
        == list(range(clothoid_range[0], clothoid_range[1] + 1)),
        "directions_are_constant_per_straight_part": all(
            flat_points[index]["direction"] == flat_points[index + 1]["direction"]
            for index in range(0, len(flat_points), 2)
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"centerline self-check failed: {checks}")
    details = {
        "edge_count": len(rows),
        "part_count": len(parts),
        "point_lld_count": len(flat_points),
        "clothoid_handle_range": list(clothoid_range),
        "edge_handle_range": list(edge_range),
        "positions_per_part": 2,
        "maximum_parts_per_edge": max(part_counts),
        "direction_units": "unsigned full circle / 65536",
        "part_position_physical_type": f"0x{part_position_type:02x}",
        "part_count_physical_type": f"0x{part_count_type:02x}",
        "centerline_reference_physical_type": f"0x{centerline_reference_type:02x}",
        "schema_size": len(schema_bytes),
        "column_table_size": len(table_bytes),
        "data_offset": data_offset,
        "payload_size": len(payload),
        "chunk_size": len(chunk),
        "checks": checks,
    }
    return chunk, output_rows, details


def run(source_path: Path, output: Path, limit: int) -> dict[str, object]:
    _progress("read-source", input=source_path, limit=limit)
    rows = read_centerline_sources(source_path, limit)
    segment_count = sum(len(row["segments"]) for row in rows)
    _progress("build", edges=len(rows), segments=segment_count)
    chunk, edge_rows, details = build_centerline_chunk(rows)
    output.mkdir(parents=True, exist_ok=True)
    chunk_path = output / "centerline_graph.decoded.bin"
    rows_path = output / "centerline_graph.edges.jsonl"
    manifest_path = output / "manifest.json"
    chunk_path.write_bytes(chunk)
    with rows_path.open("w", encoding="utf-8") as target:
        for row in edge_rows:
            target.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "source": {
            "path": str(source_path),
            "sha256": _sha256(source_path),
            "records_consumed": len(rows),
            "limit": limit,
        },
        "conversion": {
            "policy": "one two-position zero-curvature part per source segment",
            "source_vertices_preserved": True,
            "tangent_continuity_at_source_corners": False,
        },
        "artifact": {
            **details,
            "binary": chunk_path.name,
            "binary_sha256": _sha256(chunk_path),
            "edges": rows_path.name,
            "edges_sha256": _sha256(rows_path),
        },
        "writer_boundary": {
            "complete": [
                "PointLld scalar columns",
                "ClothoidCenterlineGeometryPart Positions cardinalities",
                "ClothoidCenterlineGeometry Parts cardinalities",
                "EdgeRoadElement CenterlineGeometry global handles",
                "parser and byte-for-byte self-validation",
            ],
            "deferred": [
                "merge with the integrated node/edge graph chunk",
                "remaining object/property columns",
                "ATLAS block compression and catalog/container indexes",
                "device validation",
            ],
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksums = [chunk_path, rows_path, manifest_path]
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksums),
        encoding="ascii",
    )
    _progress(
        "complete",
        output=output,
        edges=len(rows),
        parts=details["part_count"],
        point_lld=details["point_lld_count"],
        chunk_bytes=len(chunk),
        self_checks="all-pass",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="orion clothoid source JSONL")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--limit", type=int, default=100, help="edges to encode; 0 encodes all"
    )
    args = parser.parse_args()
    try:
        manifest = run(args.source, args.output, args.limit)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-centerline-writer error={error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
