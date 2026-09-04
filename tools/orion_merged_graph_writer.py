#!/usr/bin/env python3
"""Build one self-validating decoded Orion topology and centerline graph."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable

from orion_centerline_writer import (
    DIRECTION_TYPE,
    _point_lld,
    _structure_member,
    direction_to_orion,
    read_centerline_sources,
)
from orion_column_codec import (
    assemble_code1_payload,
    pack_code1_values,
    unpack_code1_values,
    validate_code1_payload_roundtrip,
)
from orion_object_writer import (
    POINT_TYPE,
    _class_composite,
    _logical_member,
    _reference_member,
    _smallest_unsigned_type,
    read_edge_reference_sources,
    read_point_llh_rows,
)
from orion_psd_reference_profile import (
    class_object_ranges,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
    serialize_exact_column_table,
    serialize_logical_schema,
)


SCHEMA_VERSION = 2


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-merged-graph-writer stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _scalar_member(index: int, name: str, type_code: int) -> dict[str, object]:
    member = _logical_member(index, name)
    member["type_code"] = type_code
    return member


def _merged_schema(
    node_count: int,
    edge_count: int,
    part_count: int,
    point_lld_count: int,
    data_offset: int,
    payload_size: int,
) -> dict[str, object]:
    point_position = {
        "index": 0,
        "kind": 1,
        "name": "Position",
        "annotations": [],
        "type_code": 0xC0,
        "type_composite_index": 0,
        "optional_flag": 0,
    }
    node_vias = _reference_member(1, "Vias", 17)
    node_vias["optional_flag"] = 1
    composites = [
        {
            "index": 0,
            "kind": 2,
            "name": "PointLlh",
            "base_index": None,
            "row_count": node_count,
            "member_count": 3,
            "members": [
                _logical_member(0, "Longitude"),
                _logical_member(1, "Latitude"),
                _logical_member(2, "Height"),
            ],
        },
        {
            "index": 1,
            "kind": 2,
            "name": "PointLld",
            "base_index": None,
            "row_count": point_lld_count,
            "member_count": 3,
            "members": [
                _scalar_member(0, "Longitude", POINT_TYPE),
                _scalar_member(1, "Latitude", POINT_TYPE),
                _scalar_member(2, "Direction", DIRECTION_TYPE),
            ],
        },
        {
            "index": 2,
            "kind": 2,
            "name": "ClothoidCenterlineGeometryPart",
            "base_index": None,
            "row_count": part_count,
            "member_count": 1,
            "members": [_structure_member(0, "Positions", 1)],
        },
        {
            "index": 3,
            "kind": 3,
            "name": "PropertyD1",
            "base_index": None,
            "row_count": edge_count,
            "member_count": 1,
            "members": [
                {
                    **_reference_member(0, "Values", 6),
                    "optional_flag": 1,
                }
            ],
        },
        {
            "index": 4,
            "kind": 2,
            "name": "AttributePart",
            "base_index": None,
            "row_count": edge_count,
            "member_count": 0,
            "members": [],
        },
        {
            "index": 5,
            "kind": 2,
            "name": "Attributes",
            "base_index": None,
            "row_count": edge_count,
            "member_count": 1,
            "members": [_structure_member(0, "Parts", 4)],
        },
        _class_composite(6, "Property", 0xFFFF, 0, []),
        _class_composite(
            7,
            "AdasProperty",
            6,
            1,
            [_scalar_member(0, "Compliant", 0x10)],
        ),
        _class_composite(
            8,
            "AudiUrbanProperty",
            6,
            1,
            [_scalar_member(0, "Urban", 0x10)],
        ),
        _class_composite(
            9,
            "UrbanProperty",
            6,
            2,
            [_scalar_member(0, "Urban", 0x10)],
        ),
        _class_composite(10, "Geometry", 0xFFFF, 0, []),
        _class_composite(11, "PointGeometry", 10, node_count, [point_position]),
        _class_composite(12, "CenterlineGeometry", 10, 0, []),
        _class_composite(
            13,
            "ClothoidCenterlineGeometry",
            12,
            edge_count,
            [_structure_member(0, "Parts", 2)],
        ),
        _class_composite(14, "Item", 0xFFFF, 0, []),
        _class_composite(15, "Atom", 14, 0, []),
        _class_composite(16, "RoadElement", 15, 0, []),
        _class_composite(
            17,
            "EdgeRoadElement",
            16,
            edge_count,
            [
                _reference_member(0, "CenterlineGeometry", 12),
                _reference_member(1, "From", 18),
                _reference_member(2, "To", 18),
                {
                    "index": 3,
                    "kind": 1,
                    "name": "Attributes",
                    "annotations": [],
                    "type_code": 0xC0,
                    "type_composite_index": 5,
                    "optional_flag": 0,
                },
            ],
        ),
        _class_composite(
            18,
            "NodeRoadElement",
            16,
            node_count,
            [_reference_member(0, "PointGeometry", 11), node_vias],
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


def _aligned_centerlines(
    edges: list[dict[str, int]], centerlines: Iterable[dict[str, object]]
) -> list[dict[str, object]]:
    rows = list(centerlines)
    edge_ids = [int(row["source_edge_id"]) for row in edges]
    centerline_ids = [int(row["source_edge_id"]) for row in rows]
    if len(set(centerline_ids)) != len(centerline_ids):
        raise ValueError("centerline source contains duplicate edge IDs")
    if edge_ids != centerline_ids:
        missing = sorted(set(edge_ids) - set(centerline_ids))[:8]
        extra = sorted(set(centerline_ids) - set(edge_ids))[:8]
        raise ValueError(
            "edge/centerline source order or IDs differ: "
            f"missing={missing} extra={extra}"
        )
    return rows


def _edge_urban_value(edge: dict[str, object]) -> int:
    """Return the firmware-backed MIB urban value for one source edge."""

    direct = edge.get("urban")
    if isinstance(direct, int) and direct in (0, 1):
        return direct
    road_attributes = edge.get("road_attributes")
    if isinstance(road_attributes, dict):
        urban = road_attributes.get("urban")
        if isinstance(urban, dict) and isinstance(urban.get("value"), bool):
            return int(urban["value"])
    geometry_parts = edge.get("geometry_parts")
    if isinstance(geometry_parts, list):
        return int(
            any(
                isinstance(part, dict)
                and isinstance(part.get("secondary_flags"), int)
                and bool(int(part["secondary_flags"]) & 0x20)
                for part in geometry_parts
            )
        )
    # Minimal unit-test/legacy sources predate the proven field. Current graph
    # exports always carry it; old sources retain the conservative zero.
    return 0


def build_merged_graph_chunk(
    nodes: Iterable[dict[str, int]],
    edges: Iterable[dict[str, int]],
    centerlines: Iterable[dict[str, object]],
) -> tuple[
    bytes,
    list[dict[str, object]],
    list[dict[str, object]],
    dict[str, object],
]:
    """Build and independently verify the merged decoded graph chunk."""

    node_list = list(nodes)
    edge_list = list(edges)
    if not node_list or not edge_list:
        raise ValueError("merged writer requires nodes and edges")
    centerline_list = _aligned_centerlines(edge_list, centerlines)

    parts: list[list[dict[str, int]]] = []
    part_counts: list[int] = []
    first_part_rows: list[int] = []
    for centerline in centerline_list:
        raw_segments = centerline["segments"]
        if not isinstance(raw_segments, list) or not raw_segments:
            raise ValueError("centerline edge has no segments")
        first_part_rows.append(len(parts))
        part_counts.append(len(raw_segments))
        for raw in raw_segments:
            if not isinstance(raw, dict):
                raise ValueError("invalid centerline segment")
            start = raw["start_mercator"]
            end = raw["end_mercator"]
            if not isinstance(start, tuple) or not isinstance(end, tuple):
                raise ValueError("normalized endpoints must be tuples")
            direction = direction_to_orion(float(raw["heading_radians"]))
            parts.append(
                [
                    _point_lld(int(start[0]), int(start[1]), direction),
                    _point_lld(int(end[0]), int(end[1]), direction),
                ]
            )
    point_lld = [point for part in parts for point in part]

    provisional = _merged_schema(
        len(node_list), len(edge_list), len(parts), len(point_lld), 1, 1
    )
    ranges = class_object_ranges(provisional)
    adas_property_range = ranges[7]
    audi_urban_property_range = ranges[8]
    urban_property_range = ranges[9]
    point_range = ranges[11]
    clothoid_range = ranges[13]
    edge_range = ranges[17]
    node_range = ranges[18]
    node_indexes = {
        int(row["source_id"]): index for index, row in enumerate(node_list)
    }
    if len(node_indexes) != len(node_list):
        raise ValueError("node source contains duplicate IDs")
    node_handles = {
        source_id: node_range[0] + index
        for source_id, index in node_indexes.items()
    }

    edge_rows: list[dict[str, object]] = []
    vias: list[list[int]] = [[] for _ in node_list]
    for index, edge in enumerate(edge_list):
        edge_handle = edge_range[0] + index
        from_source = int(edge["from_source_node_id"])
        to_source = int(edge["to_source_node_id"])
        from_handle = node_handles.get(from_source, 0)
        to_handle = node_handles.get(to_source, 0)
        from_index = node_indexes.get(from_source)
        to_index = node_indexes.get(to_source)
        if from_index is not None:
            vias[from_index].append(edge_handle)
        if to_index is not None:
            vias[to_index].append(edge_handle)
        edge_rows.append(
            {
                **edge,
                "edge_handle": edge_handle,
                "centerline_handle": clothoid_range[0] + index,
                "first_centerline_part_row": first_part_rows[index],
                "centerline_part_count": part_counts[index],
                "from_handle": from_handle,
                "to_handle": to_handle,
            }
        )
    node_rows: list[dict[str, object]] = [
        {
            "source_node_id": int(row["source_id"]),
            "point_llh_row": index,
            "point_geometry_handle": point_range[0] + index,
            "node_handle": node_range[0] + index,
            "via_edge_handles": vias[index],
        }
        for index, row in enumerate(node_list)
    ]

    via_counts = [len(values) for values in vias]
    flattened_vias = [value for values in vias for value in values]
    node_reference_type = _smallest_unsigned_type(node_range[1])
    edge_reference_type = _smallest_unsigned_type(edge_range[1])
    clothoid_reference_type = _smallest_unsigned_type(clothoid_range[1])
    part_position_type = _smallest_unsigned_type(2)
    part_count_type = _smallest_unsigned_type(max(part_counts))
    via_count_type = _smallest_unsigned_type(max(via_counts))
    urban_values = [_edge_urban_value(edge) for edge in edge_list]
    property_handles_by_edge = [
        [
            adas_property_range[0],
            urban_property_range[0] + urban_value,
            audi_urban_property_range[0],
        ]
        for urban_value in urban_values
    ]
    property_cardinalities = [3] * len(edge_list)
    property_handles = [
        handle for handles in property_handles_by_edge for handle in handles
    ]
    attribute_part_cardinalities = [1] * len(edge_list)

    columns: list[list[int]] = [
        [int(row["longitude"]) for row in node_list],
        [int(row["latitude"]) for row in node_list],
        [int(row.get("height", 0)) for row in node_list],
        [point["longitude"] for point in point_lld],
        [point["latitude"] for point in point_lld],
        [point["direction"] for point in point_lld],
        [2] * len(parts),
        property_cardinalities,
        property_handles,
        [0],
        attribute_part_cardinalities,
        [0],
        [0],
        [0, 1],
        [0] * 8,
        part_counts,
        [int(row["centerline_handle"]) for row in edge_rows],
        [int(row["from_handle"]) for row in edge_rows],
        [int(row["to_handle"]) for row in edge_rows],
        list(range(point_range[0], point_range[1] + 1)),
        via_counts,
        flattened_vias,
        [0],
    ]
    physical_types = [
        POINT_TYPE,
        POINT_TYPE,
        POINT_TYPE,
        POINT_TYPE,
        POINT_TYPE,
        DIRECTION_TYPE,
        part_position_type,
        _smallest_unsigned_type(3),
        _smallest_unsigned_type(max(property_handles)),
        0x25,
        _smallest_unsigned_type(1),
        0x20,
        0x20,
        0x20,
        0x10,
        part_count_type,
        clothoid_reference_type,
        node_reference_type,
        node_reference_type,
        _smallest_unsigned_type(point_range[1]),
        via_count_type,
        edge_reference_type,
        0x25,
    ]
    tags = [
        2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2,
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1,
    ]
    payloads = [
        pack_code1_values(type_code, values)
        for type_code, values in zip(physical_types, columns)
    ]
    descriptors = [
        {"tag": tag, "type_code": type_code, "size": len(payload)}
        for tag, type_code, payload in zip(tags, physical_types, payloads)
    ]
    table = {
        "descriptors": descriptors,
        "compression_codes": [1] * len(descriptors),
    }
    table_bytes = serialize_exact_column_table(table)
    payload = assemble_code1_payload(descriptors, payloads)
    provisional = _merged_schema(
        len(node_list),
        len(edge_list),
        len(parts),
        len(point_lld),
        1,
        len(payload),
    )
    schema_size = len(serialize_logical_schema(provisional))
    data_offset = schema_size + len(table_bytes)
    schema_bytes = serialize_logical_schema(
        _merged_schema(
            len(node_list),
            len(edge_list),
            len(parts),
            len(point_lld),
            data_offset,
            len(payload),
        )
    )
    chunk = schema_bytes + table_bytes + payload

    parsed_schema = parse_logical_schema(chunk)
    if parsed_schema is None:
        raise ValueError("merged graph schema cannot be reparsed")
    parsed_table = parse_exact_column_table(chunk, parsed_schema)
    if parsed_table is None:
        raise ValueError("merged graph table cannot be reparsed")
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
    group_counts = {
        (group["composite_name"], group["member_name"]): group["part_count"]
        for group in groups
    }
    expected_groups = {
        ("PointLlh", "Longitude"): 1,
        ("PointLlh", "Latitude"): 1,
        ("PointLlh", "Height"): 1,
        ("PointLld", "Longitude"): 1,
        ("PointLld", "Latitude"): 1,
        ("PointLld", "Direction"): 1,
        ("ClothoidCenterlineGeometryPart", "Positions"): 1,
        ("PropertyD1", "Values"): 3,
        ("Attributes", "Parts"): 1,
        ("AdasProperty", "Compliant"): 1,
        ("AudiUrbanProperty", "Urban"): 1,
        ("UrbanProperty", "Urban"): 1,
        ("PointGeometry", "Position"): 1,
        ("ClothoidCenterlineGeometry", "Parts"): 1,
        ("EdgeRoadElement", "CenterlineGeometry"): 1,
        ("EdgeRoadElement", "From"): 1,
        ("EdgeRoadElement", "To"): 1,
        ("EdgeRoadElement", "Attributes"): 0,
        ("NodeRoadElement", "PointGeometry"): 1,
        ("NodeRoadElement", "Vias"): 3,
    }
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
        "logical_members_grouped": group_counts == expected_groups,
        "code1_values_identical": decoded_columns == columns,
        "source_edge_ids_aligned": [
            int(row["source_edge_id"]) for row in edge_list
        ]
        == [int(row["source_edge_id"]) for row in centerline_list],
        "every_part_has_two_positions": decoded_columns[6] == [2] * len(parts),
        "property_lists_have_three_mandatory_handles": decoded_columns[7]
        == property_cardinalities
        and decoded_columns[8] == property_handles
        and decoded_columns[9] == [0],
        "attributes_have_one_part_per_edge": decoded_columns[10]
        == attribute_part_cardinalities
        and sum(decoded_columns[10]) == len(edge_list),
        "adas_and_audi_urban_values_are_explicit_baseline_fallback": decoded_columns[11:13]
        == [[0], [0]],
        "urban_values_are_firmware_backed_boolean_rows": decoded_columns[13]
        == [0, 1]
        and all(
            handles[1] == urban_property_range[0] + value
            for handles, value in zip(property_handles_by_edge, urban_values)
        ),
        "mandatory_property_order_matches_original_corpus": all(
            handles[0] == adas_property_range[0]
            and urban_property_range[0] <= handles[1] <= urban_property_range[1]
            and handles[2] == audi_urban_property_range[0]
            for handles in property_handles_by_edge
        ),
        "centerline_part_cardinalities_match": decoded_columns[15] == part_counts
        and sum(decoded_columns[15]) == len(parts),
        "every_edge_targets_own_clothoid": decoded_columns[16]
        == list(range(clothoid_range[0], clothoid_range[1] + 1)),
        "every_nonzero_endpoint_targets_node": all(
            node_range[0] <= value <= node_range[1]
            for value in decoded_columns[17] + decoded_columns[18]
            if value
        ),
        "node_point_geometry_handles_match": decoded_columns[19]
        == list(range(point_range[0], point_range[1] + 1)),
        "via_cardinalities_match": decoded_columns[20] == via_counts
        and sum(decoded_columns[20]) == len(decoded_columns[21]),
        "every_via_targets_edge": all(
            edge_range[0] <= value <= edge_range[1]
            for value in decoded_columns[21]
        ),
        "endpoint_incidence_matches_vias": len(decoded_columns[21])
        == sum(value != 0 for value in decoded_columns[17])
        + sum(value != 0 for value in decoded_columns[18]),
        "directions_constant_per_straight_part": all(
            point_lld[index]["direction"] == point_lld[index + 1]["direction"]
            for index in range(0, len(point_lld), 2)
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"merged graph self-check failed: {checks}")
    details = {
        "node_count": len(node_list),
        "edge_count": len(edge_list),
        "centerline_part_count": len(parts),
        "point_lld_count": len(point_lld),
        "point_geometry_handle_range": list(point_range),
        "adas_property_handle_range": list(adas_property_range),
        "audi_urban_property_handle_range": list(audi_urban_property_range),
        "urban_property_handle_range": list(urban_property_range),
        "clothoid_handle_range": list(clothoid_range),
        "edge_handle_range": list(edge_range),
        "node_handle_range": list(node_range),
        "via_reference_count": len(flattened_vias),
        "maximum_node_degree": max(via_counts),
        "maximum_parts_per_edge": max(part_counts),
        "attribute_part_count": sum(attribute_part_cardinalities),
        "property_list_count": len(property_cardinalities),
        "property_handle_count": len(property_handles),
        "urban_edge_count": sum(urban_values),
        "property_value_policy": (
            "Urban comes from MIB geometry secondary flag bit 5; Adas zero "
            "matches clean original baseline chunks; AudiUrban remains "
            "conservative zero pending source-semantic mapping"
        ),
        "positions_per_part": 2,
        "direction_units": "unsigned full circle / 65536",
        "schema_size": len(schema_bytes),
        "column_table_size": len(table_bytes),
        "data_offset": data_offset,
        "payload_size": len(payload),
        "chunk_size": len(chunk),
        "checks": checks,
    }
    return chunk, node_rows, edge_rows, details


def run(
    node_source: Path,
    edge_source: Path,
    centerline_source: Path,
    output: Path,
    node_limit: int,
    edge_limit: int,
) -> dict[str, object]:
    _progress("read-sources", node_limit=node_limit, edge_limit=edge_limit)
    nodes = read_point_llh_rows(node_source, node_limit)
    edges = read_edge_reference_sources(edge_source, edge_limit)
    centerlines = read_centerline_sources(centerline_source, edge_limit)
    _progress(
        "build",
        nodes=len(nodes),
        edges=len(edges),
        segments=sum(len(row["segments"]) for row in centerlines),
    )
    chunk, node_rows, edge_rows, details = build_merged_graph_chunk(
        nodes, edges, centerlines
    )
    output.mkdir(parents=True, exist_ok=True)
    chunk_path = output / "merged_graph.decoded.bin"
    nodes_path = output / "merged_graph.nodes.jsonl"
    edges_path = output / "merged_graph.edges.jsonl"
    manifest_path = output / "manifest.json"
    chunk_path.write_bytes(chunk)
    for path, rows in ((nodes_path, node_rows), (edges_path, edge_rows)):
        with path.open("w", encoding="utf-8") as target:
            for row in rows:
                target.write(
                    json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
                )
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "sources": {
            "nodes": {
                "path": str(node_source),
                "sha256": _sha256(node_source),
                "records_consumed": len(nodes),
                "limit": node_limit,
            },
            "edges": {
                "path": str(edge_source),
                "sha256": _sha256(edge_source),
                "records_consumed": len(edges),
                "limit": edge_limit,
            },
            "centerlines": {
                "path": str(centerline_source),
                "sha256": _sha256(centerline_source),
                "records_consumed": len(centerlines),
                "limit": edge_limit,
            },
        },
        "conversion": {
            "centerline_policy": "one two-position zero-curvature part per source segment",
            "source_vertices_preserved": True,
            "tangent_continuity_at_source_corners": False,
        },
        "artifact": {
            **details,
            "binary": chunk_path.name,
            "binary_sha256": _sha256(chunk_path),
            "nodes": nodes_path.name,
            "nodes_sha256": _sha256(nodes_path),
            "edges": edges_path.name,
            "edges_sha256": _sha256(edges_path),
        },
        "writer_boundary": {
            "complete": [
                "PointLlh and direct NodeRoadElement PointGeometry handles",
                "PointLld and ClothoidCenterlineGeometry parts",
                "EdgeRoadElement CenterlineGeometry, From and To handles",
                "implicit EdgeRoadElement Attributes structure binding",
                "Attributes Parts and populated PropertyD1 list structure",
                "mandatory AdasProperty, UrbanProperty and AudiUrbanProperty handles",
                "firmware-backed UrbanProperty 0/1 selection per edge",
                "explicit conservative zero values for AdasProperty and AudiUrbanProperty",
                "NodeRoadElement Vias adjacency",
                "one global class handle space",
                "parser and byte-for-byte self-validation",
            ],
            "deferred": [
                "source-semantic AudiUrbanProperty value; Adas is corpus-confirmed zero",
                "optional speed, lane, restriction and remaining property columns",
                "ATLAS block compression",
                "catalog/index records",
                "container placement and checksums",
                "device validation",
            ],
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_paths = [chunk_path, nodes_path, edges_path, manifest_path]
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
    )
    _progress(
        "complete",
        output=output,
        chunk_bytes=len(chunk),
        point_lld=details["point_lld_count"],
        parts=details["centerline_part_count"],
        vias=details["via_reference_count"],
        self_checks="all-pass",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nodes", type=Path)
    parser.add_argument("--edges", type=Path, required=True)
    parser.add_argument("--clothoids", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--node-limit", type=int, default=100)
    parser.add_argument("--edge-limit", type=int, default=100)
    args = parser.parse_args()
    try:
        manifest = run(
            args.nodes,
            args.edges,
            args.clothoids,
            args.output,
            args.node_limit,
            args.edge_limit,
        )
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-merged-graph-writer error={error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
