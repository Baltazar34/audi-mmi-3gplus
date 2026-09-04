#!/usr/bin/env python3
"""Build self-validating decoded Orion point and graph objects from MIB JSONL.

The writer emits the exact logical-schema, physical-descriptor, codec-array and
code-1 payload layout consumed by the existing Orion parser.  With an edge
source it also emits an integrated PointLlh/PointGeometry/Edge/Node graph with
direct From/To handles and Node Vias adjacency.  Centerline/property columns,
ATLAS block compression, catalog/index entries and container placement remain
later layers.
"""

from __future__ import annotations

import argparse
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
from pathlib import Path
import sys
from typing import Iterable

from orion_column_codec import (
    assemble_code1_payload,
    pack_code1_values,
    unpack_code1_values,
    validate_code1_payload_roundtrip,
)
from orion_psd_reference_profile import (
    class_object_ranges,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
    serialize_exact_column_table,
    serialize_logical_schema,
)


SCHEMA_VERSION = 1
COORDINATE_SCALE = 10_000_000
POINT_TYPE = 0x35


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-object-writer stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def coordinate_to_orion(value: object) -> int:
    """Convert WGS84 degrees to signed 1e-7-degree Orion units."""

    decimal = Decimal(str(value)) * COORDINATE_SCALE
    return int(decimal.quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def read_point_llh_rows(
    source_path: Path, limit: int = 0
) -> list[dict[str, int]]:
    """Read validated PointLlh source rows from the MIB graph export."""

    if limit < 0:
        raise ValueError("limit must not be negative")
    rows: list[dict[str, int]] = []
    with source_path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            coordinate = record.get("coordinate")
            wgs84 = coordinate.get("wgs84") if isinstance(coordinate, dict) else None
            if not isinstance(wgs84, list) or len(wgs84) != 2:
                raise ValueError(f"line {line_number}: missing coordinate.wgs84")
            rows.append(
                {
                    "source_id": int(record["node_id"]),
                    "longitude": coordinate_to_orion(wgs84[0]),
                    "latitude": coordinate_to_orion(wgs84[1]),
                    "height": 0,
                }
            )
            if limit and len(rows) >= limit:
                break
    if not rows:
        raise ValueError("source contains no PointLlh rows")
    return rows


def read_edge_reference_sources(
    source_path: Path, limit: int = 0
) -> list[dict[str, int]]:
    """Read From/To source IDs from the normalized MIB graph export."""

    if limit < 0:
        raise ValueError("edge limit must not be negative")
    rows: list[dict[str, int]] = []
    with source_path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            record = json.loads(line)
            from_value = record.get("from")
            to_value = record.get("to")
            if not isinstance(from_value, dict) or not isinstance(to_value, dict):
                raise ValueError(f"line {line_number}: missing from/to objects")
            road_attributes = record.get("road_attributes")
            urban_value = None
            if isinstance(road_attributes, dict):
                urban = road_attributes.get("urban")
                if isinstance(urban, dict) and isinstance(urban.get("value"), bool):
                    urban_value = int(urban["value"])
            if urban_value is None:
                geometry_parts = record.get("geometry_parts")
                if isinstance(geometry_parts, list):
                    urban_value = int(
                        any(
                            isinstance(part, dict)
                            and isinstance(part.get("secondary_flags"), int)
                            and bool(int(part["secondary_flags"]) & 0x20)
                            for part in geometry_parts
                        )
                    )
                else:
                    urban_value = 0
            rows.append(
                {
                    "source_edge_id": int(record["edge_id"]),
                    "from_source_node_id": int(from_value["node_id"]),
                    "to_source_node_id": int(to_value["node_id"]),
                    "urban": urban_value,
                }
            )
            if limit and len(rows) >= limit:
                break
    if not rows:
        raise ValueError("source contains no EdgeRoadElement rows")
    return rows


def _logical_member(index: int, name: str) -> dict[str, object]:
    return {
        "index": index,
        "kind": 1,
        "name": name,
        "annotations": [],
        "type_code": POINT_TYPE,
        "type_composite_index": None,
        "optional_flag": 0,
    }


def _schema(row_count: int, data_offset: int, payload_size: int) -> dict[str, object]:
    members = [
        _logical_member(0, "Longitude"),
        _logical_member(1, "Latitude"),
        _logical_member(2, "Height"),
    ]
    return {
        "map_name": "Map",
        "data_offset": data_offset,
        "payload_size": payload_size,
        # Header words 2..4 are preserved fields whose runtime semantics are
        # still unproven.  Zero is explicit in this synthetic writer layer.
        "header_values": [data_offset, payload_size, 0, 0, 0],
        "composite_count": 1,
        "composites": [
            {
                "index": 0,
                "kind": 2,
                "name": "PointLlh",
                "base_index": None,
                "row_count": row_count,
                "member_count": len(members),
                "members": members,
            }
        ],
    }


def build_point_llh_chunk(
    rows: Iterable[dict[str, int]],
) -> tuple[bytes, dict[str, object]]:
    """Create and independently reparse one decoded Orion PointLlh chunk."""

    row_list = list(rows)
    if not row_list:
        raise ValueError("at least one PointLlh row is required")
    source_columns = [
        [int(row["longitude"]) for row in row_list],
        [int(row["latitude"]) for row in row_list],
        [int(row.get("height", 0)) for row in row_list],
    ]
    payloads = [pack_code1_values(POINT_TYPE, values) for values in source_columns]
    descriptors = [
        {"tag": 2, "type_code": POINT_TYPE, "size": len(payload)}
        for payload in payloads
    ]
    table = {"descriptors": descriptors, "compression_codes": [1, 1, 1]}
    table_bytes = serialize_exact_column_table(table)
    payload = assemble_code1_payload(descriptors, payloads)

    provisional_schema = _schema(len(row_list), 1, len(payload))
    schema_size = len(serialize_logical_schema(provisional_schema))
    data_offset = schema_size + len(table_bytes)
    schema_bytes = serialize_logical_schema(
        _schema(len(row_list), data_offset, len(payload))
    )
    chunk = schema_bytes + table_bytes + payload

    parsed_schema = parse_logical_schema(chunk)
    if parsed_schema is None:
        raise ValueError("generated logical schema cannot be reparsed")
    parsed_table = parse_exact_column_table(chunk, parsed_schema)
    if parsed_table is None:
        raise ValueError("generated physical column table cannot be reparsed")
    groups = group_serialized_parts(parsed_schema, parsed_table["descriptors"])
    columns = validate_code1_payload_roundtrip(
        chunk,
        int(parsed_schema["data_offset"]),
        parsed_table["descriptors"],
        parsed_table["compression_codes"],
    )
    decoded_columns = [
        unpack_code1_values(
            column.type_code,
            chunk[column.payload_offset : column.payload_offset + column.payload_size],
            len(row_list),
        )
        for column in columns
    ]

    checks = {
        "schema_byte_identical": serialize_logical_schema(parsed_schema) == schema_bytes,
        "column_table_byte_identical": (
            serialize_exact_column_table(parsed_table) == table_bytes
        ),
        "whole_chunk_byte_identical": (
            serialize_logical_schema(parsed_schema)
            + serialize_exact_column_table(parsed_table)
            + chunk[int(parsed_schema["data_offset"]) :]
            == chunk
        ),
        "logical_members_grouped": (
            len(groups) == 3
            and [group["member_name"] for group in groups]
            == ["Longitude", "Latitude", "Height"]
            and all(group["part_count"] == 1 for group in groups)
        ),
        "code1_values_identical": decoded_columns == source_columns,
        "payload_size_matches_header": len(payload)
        == int(parsed_schema["payload_size"]),
    }
    if not all(checks.values()):
        raise ValueError(f"generated PointLlh self-check failed: {checks}")

    details = {
        "row_count": len(row_list),
        "schema_size": len(schema_bytes),
        "column_table_size": len(table_bytes),
        "data_offset": data_offset,
        "payload_size": len(payload),
        "chunk_size": len(chunk),
        "columns": [
            {
                "name": name,
                "logical_type": f"0x{POINT_TYPE:02x}",
                "physical_type": f"0x{POINT_TYPE:02x}",
                "codec": 1,
                "payload_size": len(column_payload),
                "minimum": min(values),
                "maximum": max(values),
            }
            for name, values, column_payload in zip(
                ("Longitude", "Latitude", "Height"), source_columns, payloads
            )
        ],
        "checks": checks,
    }
    return chunk, details


def _class_composite(
    index: int,
    name: str,
    base_index: int,
    row_count: int,
    members: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "index": index,
        "kind": 1,
        "name": name,
        "base_index": base_index,
        "row_count": row_count,
        "member_count": len(members),
        "members": members,
    }


def _reference_member(
    index: int, name: str, target_composite_index: int
) -> dict[str, object]:
    return {
        "index": index,
        "kind": 1,
        "name": name,
        "annotations": [],
        "type_code": 0xB0,
        "type_composite_index": target_composite_index,
        "optional_flag": 0,
    }


def _smallest_unsigned_type(maximum: int) -> int:
    if maximum < 0:
        raise ValueError("reference maximum must not be negative")
    for type_code, bits in ((0x20, 1), (0x21, 2), (0x22, 4), (0x23, 8), (0x24, 16), (0x25, 32)):
        if maximum < 1 << bits:
            return type_code
    raise ValueError("reference handle exceeds Orion 32-bit range")


def _graph_reference_schema(
    edge_count: int, node_count: int, data_offset: int, payload_size: int
) -> dict[str, object]:
    composites = [
        _class_composite(0, "Item", 0xFFFF, 0, []),
        _class_composite(1, "Atom", 0, 0, []),
        _class_composite(2, "RoadElement", 1, 0, []),
        _class_composite(
            3,
            "EdgeRoadElement",
            2,
            edge_count,
            [_reference_member(0, "From", 4), _reference_member(1, "To", 4)],
        ),
        _class_composite(4, "NodeRoadElement", 2, node_count, []),
    ]
    return {
        "map_name": "Map",
        "data_offset": data_offset,
        "payload_size": payload_size,
        "header_values": [data_offset, payload_size, 0, 0, 0],
        "composite_count": len(composites),
        "composites": composites,
    }


def build_graph_reference_chunk(
    nodes: Iterable[dict[str, int]], edges: Iterable[dict[str, int]]
) -> tuple[bytes, list[dict[str, int]], dict[str, object]]:
    """Emit direct global From/To handles using the original PSD3 allocator."""

    node_list = list(nodes)
    edge_list = list(edges)
    if not node_list or not edge_list:
        raise ValueError("graph reference writer requires nodes and edges")
    provisional = _graph_reference_schema(len(edge_list), len(node_list), 1, 1)
    ranges = class_object_ranges(provisional)
    edge_range = ranges[3]
    node_range = ranges[4]
    node_handles = {
        int(row["source_id"]): node_range[0] + index
        for index, row in enumerate(node_list)
    }
    reference_rows = [
        {
            **edge,
            "edge_handle": edge_range[0] + index,
            "from_handle": node_handles.get(int(edge["from_source_node_id"]), 0),
            "to_handle": node_handles.get(int(edge["to_source_node_id"]), 0),
        }
        for index, edge in enumerate(edge_list)
    ]
    source_columns = [
        [row["from_handle"] for row in reference_rows],
        [row["to_handle"] for row in reference_rows],
    ]
    physical_type = _smallest_unsigned_type(node_range[1])
    payloads = [pack_code1_values(physical_type, values) for values in source_columns]
    descriptors = [
        {"tag": 2, "type_code": physical_type, "size": len(payload)}
        for payload in payloads
    ]
    table = {"descriptors": descriptors, "compression_codes": [1, 1]}
    table_bytes = serialize_exact_column_table(table)
    payload = assemble_code1_payload(descriptors, payloads)
    provisional = _graph_reference_schema(
        len(edge_list), len(node_list), 1, len(payload)
    )
    schema_size = len(serialize_logical_schema(provisional))
    data_offset = schema_size + len(table_bytes)
    schema_bytes = serialize_logical_schema(
        _graph_reference_schema(
            len(edge_list), len(node_list), data_offset, len(payload)
        )
    )
    chunk = schema_bytes + table_bytes + payload

    parsed_schema = parse_logical_schema(chunk)
    if parsed_schema is None:
        raise ValueError("generated graph reference schema cannot be reparsed")
    parsed_table = parse_exact_column_table(chunk, parsed_schema)
    if parsed_table is None:
        raise ValueError("generated graph reference table cannot be reparsed")
    groups = group_serialized_parts(parsed_schema, parsed_table["descriptors"])
    layouts = validate_code1_payload_roundtrip(
        chunk,
        int(parsed_schema["data_offset"]),
        parsed_table["descriptors"],
        parsed_table["compression_codes"],
    )
    decoded_columns = [
        unpack_code1_values(
            layout.type_code,
            chunk[layout.payload_offset : layout.payload_offset + layout.payload_size],
            len(edge_list),
        )
        for layout in layouts
    ]
    parsed_ranges = class_object_ranges(parsed_schema)
    nonzero_references = [
        value for values in decoded_columns for value in values if value != 0
    ]
    checks = {
        "schema_byte_identical": serialize_logical_schema(parsed_schema) == schema_bytes,
        "column_table_byte_identical": serialize_exact_column_table(parsed_table)
        == table_bytes,
        "whole_chunk_byte_identical": (
            serialize_logical_schema(parsed_schema)
            + serialize_exact_column_table(parsed_table)
            + chunk[int(parsed_schema["data_offset"]) :]
            == chunk
        ),
        "reference_members_grouped": len(groups) == 2
        and [group["member_name"] for group in groups] == ["From", "To"],
        "class_handle_ranges_identical": parsed_ranges == ranges,
        "code1_reference_values_identical": decoded_columns == source_columns,
        "every_nonzero_reference_targets_node": all(
            node_range[0] <= value <= node_range[1] for value in nonzero_references
        ),
        "zero_only_for_absent_source_node": all(
            (row["from_handle"] == 0)
            == (row["from_source_node_id"] not in node_handles)
            and (row["to_handle"] == 0)
            == (row["to_source_node_id"] not in node_handles)
            for row in reference_rows
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"generated graph reference self-check failed: {checks}")
    details = {
        "edge_count": len(edge_list),
        "node_count": len(node_list),
        "edge_handle_range": list(edge_range),
        "node_handle_range": list(node_range),
        "physical_type": f"0x{physical_type:02x}",
        "schema_size": len(schema_bytes),
        "column_table_size": len(table_bytes),
        "data_offset": data_offset,
        "payload_size": len(payload),
        "chunk_size": len(chunk),
        "from_zero_sentinels": source_columns[0].count(0),
        "to_zero_sentinels": source_columns[1].count(0),
        "checks": checks,
    }
    return chunk, reference_rows, details


def _integrated_graph_schema(
    edge_count: int, node_count: int, data_offset: int, payload_size: int
) -> dict[str, object]:
    position_member = {
        "index": 0,
        "kind": 1,
        "name": "Position",
        "annotations": [],
        "type_code": 0xC0,
        "type_composite_index": 0,
        "optional_flag": 0,
    }
    node_members = [
        _reference_member(0, "PointGeometry", 3),
        {
            **_reference_member(1, "Vias", 7),
            "optional_flag": 1,
        },
    ]
    point_members = [
        _logical_member(0, "Longitude"),
        _logical_member(1, "Latitude"),
        _logical_member(2, "Height"),
    ]
    composites = [
        {
            "index": 0,
            "kind": 2,
            "name": "PointLlh",
            "base_index": None,
            "row_count": node_count,
            "member_count": 3,
            "members": point_members,
        },
        {
            "index": 1,
            "kind": 2,
            "name": "Attributes",
            "base_index": None,
            "row_count": edge_count,
            "member_count": 0,
            "members": [],
        },
        {
            "index": 2,
            "kind": 1,
            "name": "Geometry",
            "base_index": 0xFFFF,
            "row_count": 0,
            "member_count": 0,
            "members": [],
        },
        _class_composite(3, "PointGeometry", 2, node_count, [position_member]),
        _class_composite(4, "Item", 0xFFFF, 0, []),
        _class_composite(5, "Atom", 4, 0, []),
        _class_composite(6, "RoadElement", 5, 0, []),
        _class_composite(
            7,
            "EdgeRoadElement",
            6,
            edge_count,
            [
                _reference_member(0, "From", 8),
                _reference_member(1, "To", 8),
                {
                    "index": 2,
                    "kind": 1,
                    "name": "Attributes",
                    "annotations": [],
                    "type_code": 0xC0,
                    "type_composite_index": 1,
                    "optional_flag": 0,
                },
            ],
        ),
        _class_composite(8, "NodeRoadElement", 6, node_count, node_members),
    ]
    return {
        "map_name": "Map",
        "data_offset": data_offset,
        "payload_size": payload_size,
        "header_values": [data_offset, payload_size, 0, 0, 0],
        "composite_count": len(composites),
        "composites": composites,
    }


def build_integrated_graph_chunk(
    nodes: Iterable[dict[str, int]], edges: Iterable[dict[str, int]]
) -> tuple[bytes, list[dict[str, object]], list[dict[str, int]], dict[str, object]]:
    """Build PointLlh, PointGeometry, Edge, Node and Vias in one chunk."""

    node_list = list(nodes)
    edge_list = list(edges)
    if not node_list or not edge_list:
        raise ValueError("integrated graph writer requires nodes and edges")
    provisional = _integrated_graph_schema(len(edge_list), len(node_list), 1, 1)
    ranges = class_object_ranges(provisional)
    point_range, edge_range, node_range = ranges[3], ranges[7], ranges[8]
    node_indexes = {
        int(row["source_id"]): index for index, row in enumerate(node_list)
    }
    node_handles = {
        source_id: node_range[0] + index
        for source_id, index in node_indexes.items()
    }
    reference_rows = [
        {
            **edge,
            "edge_handle": edge_range[0] + index,
            "from_handle": node_handles.get(int(edge["from_source_node_id"]), 0),
            "to_handle": node_handles.get(int(edge["to_source_node_id"]), 0),
        }
        for index, edge in enumerate(edge_list)
    ]
    vias: list[list[int]] = [[] for _ in node_list]
    for row in reference_rows:
        from_index = node_indexes.get(int(row["from_source_node_id"]))
        to_index = node_indexes.get(int(row["to_source_node_id"]))
        if from_index is not None:
            vias[from_index].append(int(row["edge_handle"]))
        if to_index is not None:
            vias[to_index].append(int(row["edge_handle"]))
    node_bindings: list[dict[str, object]] = [
        {
            "source_node_id": int(row["source_id"]),
            "point_llh_row": index,
            "point_geometry_handle": point_range[0] + index,
            "node_handle": node_range[0] + index,
            "via_edge_handles": vias[index],
        }
        for index, row in enumerate(node_list)
    ]

    coordinate_columns = [
        [int(row["longitude"]) for row in node_list],
        [int(row["latitude"]) for row in node_list],
        [int(row.get("height", 0)) for row in node_list],
    ]
    from_values = [int(row["from_handle"]) for row in reference_rows]
    to_values = [int(row["to_handle"]) for row in reference_rows]
    point_geometry_values = list(range(point_range[0], point_range[1] + 1))
    via_counts = [len(values) for values in vias]
    flattened_vias = [value for values in vias for value in values]
    node_reference_type = _smallest_unsigned_type(node_range[1])
    via_count_type = _smallest_unsigned_type(max(via_counts))
    edge_reference_type = _smallest_unsigned_type(edge_range[1])

    payloads = [
        *(pack_code1_values(POINT_TYPE, values) for values in coordinate_columns),
        pack_code1_values(0x10, [0] * 8),
        pack_code1_values(node_reference_type, from_values),
        pack_code1_values(node_reference_type, to_values),
        pack_code1_values(
            _smallest_unsigned_type(point_range[1]), point_geometry_values
        ),
        pack_code1_values(via_count_type, via_counts),
        pack_code1_values(edge_reference_type, flattened_vias),
        pack_code1_values(0x25, [0]),
    ]
    physical_types = [
        POINT_TYPE,
        POINT_TYPE,
        POINT_TYPE,
        0x10,
        node_reference_type,
        node_reference_type,
        _smallest_unsigned_type(point_range[1]),
        via_count_type,
        edge_reference_type,
        0x25,
    ]
    tags = [2, 2, 2, 2, 2, 2, 2, 2, 2, 1]
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
    provisional = _integrated_graph_schema(
        len(edge_list), len(node_list), 1, len(payload)
    )
    schema_size = len(serialize_logical_schema(provisional))
    data_offset = schema_size + len(table_bytes)
    schema_bytes = serialize_logical_schema(
        _integrated_graph_schema(
            len(edge_list), len(node_list), data_offset, len(payload)
        )
    )
    chunk = schema_bytes + table_bytes + payload

    parsed_schema = parse_logical_schema(chunk)
    if parsed_schema is None:
        raise ValueError("integrated graph schema cannot be reparsed")
    parsed_table = parse_exact_column_table(chunk, parsed_schema)
    if parsed_table is None:
        raise ValueError("integrated graph table cannot be reparsed")
    groups = group_serialized_parts(parsed_schema, parsed_table["descriptors"])
    layouts = validate_code1_payload_roundtrip(
        chunk,
        int(parsed_schema["data_offset"]),
        parsed_table["descriptors"],
        parsed_table["compression_codes"],
    )
    decoded_from = unpack_code1_values(
        node_reference_type,
        chunk[
            layouts[4].payload_offset : layouts[4].payload_offset
            + layouts[4].payload_size
        ],
        len(edge_list),
    )
    decoded_to = unpack_code1_values(
        node_reference_type,
        chunk[
            layouts[5].payload_offset : layouts[5].payload_offset
            + layouts[5].payload_size
        ],
        len(edge_list),
    )
    decoded_counts = unpack_code1_values(
        via_count_type,
        chunk[
            layouts[7].payload_offset : layouts[7].payload_offset
            + layouts[7].payload_size
        ],
        len(node_list),
    )
    decoded_point_geometry = unpack_code1_values(
        _smallest_unsigned_type(point_range[1]),
        chunk[
            layouts[6].payload_offset : layouts[6].payload_offset
            + layouts[6].payload_size
        ],
        len(node_list),
    )
    decoded_vias = unpack_code1_values(
        edge_reference_type,
        chunk[
            layouts[8].payload_offset : layouts[8].payload_offset
            + layouts[8].payload_size
        ],
        len(flattened_vias),
    )
    point_group = next(
        group
        for group in groups
        if group["composite_name"] == "NodeRoadElement"
        and group["member_name"] == "PointGeometry"
    )
    vias_group = next(
        group
        for group in groups
        if group["composite_name"] == "NodeRoadElement"
        and group["member_name"] == "Vias"
    )
    edge_attributes_group = next(
        group
        for group in groups
        if group["composite_name"] == "EdgeRoadElement"
        and group["member_name"] == "Attributes"
    )
    checks = {
        "schema_byte_identical": serialize_logical_schema(parsed_schema) == schema_bytes,
        "column_table_byte_identical": serialize_exact_column_table(parsed_table)
        == table_bytes,
        "whole_chunk_byte_identical": (
            serialize_logical_schema(parsed_schema)
            + serialize_exact_column_table(parsed_table)
            + chunk[int(parsed_schema["data_offset"]) :]
            == chunk
        ),
        "class_handle_ranges_identical": class_object_ranges(parsed_schema) == ranges,
        "edge_attributes_binding_is_implicit": edge_attributes_group["part_count"]
        == 0,
        "point_geometry_references_are_direct": point_group["part_count"] == 1
        and decoded_point_geometry == point_geometry_values,
        "vias_has_cardinality_values_and_default_parts": vias_group["part_count"]
        == 3,
        "from_to_values_identical": decoded_from == from_values
        and decoded_to == to_values,
        "via_cardinalities_match_flattened_count": decoded_counts == via_counts
        and sum(decoded_counts) == len(decoded_vias),
        "via_values_identical": decoded_vias == flattened_vias,
        "every_via_targets_edge": all(
            edge_range[0] <= value <= edge_range[1] for value in decoded_vias
        ),
        "local_endpoint_incidence_matches_vias": len(decoded_vias)
        == sum(value != 0 for value in from_values)
        + sum(value != 0 for value in to_values),
    }
    if not all(checks.values()):
        raise ValueError(f"integrated graph self-check failed: {checks}")
    details = {
        "node_count": len(node_list),
        "edge_count": len(edge_list),
        "point_geometry_handle_range": list(point_range),
        "edge_handle_range": list(edge_range),
        "node_handle_range": list(node_range),
        "node_reference_physical_type": f"0x{node_reference_type:02x}",
        "via_count_physical_type": f"0x{via_count_type:02x}",
        "edge_reference_physical_type": f"0x{edge_reference_type:02x}",
        "via_reference_count": len(flattened_vias),
        "maximum_node_degree": max(via_counts),
        "schema_size": len(schema_bytes),
        "column_table_size": len(table_bytes),
        "data_offset": data_offset,
        "payload_size": len(payload),
        "chunk_size": len(chunk),
        "checks": checks,
    }
    return chunk, node_bindings, reference_rows, details


def run(
    source_path: Path,
    output: Path,
    limit: int,
    edge_source_path: Path | None = None,
    edge_limit: int = 0,
) -> dict[str, object]:
    _progress("read-source", input=source_path, limit=limit)
    rows = read_point_llh_rows(source_path, limit)
    _progress("build", rows=len(rows))
    chunk, details = build_point_llh_chunk(rows)

    output.mkdir(parents=True, exist_ok=True)
    chunk_path = output / "point_llh.decoded.bin"
    rows_path = output / "point_llh.rows.jsonl"
    manifest_path = output / "manifest.json"
    temporary_chunk = chunk_path.with_suffix(".bin.tmp")
    temporary_rows = rows_path.with_suffix(".jsonl.tmp")
    temporary_chunk.write_bytes(chunk)
    with temporary_rows.open("w", encoding="utf-8") as target:
        for index, row in enumerate(rows):
            target.write(
                json.dumps(
                    {"row_index": index, **row}, separators=(",", ":"), sort_keys=True
                )
                + "\n"
            )
    temporary_chunk.replace(chunk_path)
    temporary_rows.replace(rows_path)

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
            "source_model": "MIB Basic graph node coordinate.wgs84",
            "target_model": "Orion Map/PointLlh",
            "coordinate_units": "signed degrees times 10,000,000",
            "height_policy": "zero until a source elevation layer is available",
        },
        "writer_boundary": {
            "complete": [
                "logical schema",
                "physical descriptors",
                "compression-code array",
                "code-1 scalar payload",
                "parser and byte-for-byte self-validation",
            ],
            "deferred": [
                "EdgeRoadElement CenterlineGeometry and remaining object/property columns",
                "ATLAS block compression",
                "catalog/index records",
                "container placement and checksums",
                "device validation",
            ],
        },
        "artifact": {
            **details,
            "binary": chunk_path.name,
            "binary_sha256": _sha256(chunk_path),
            "rows": rows_path.name,
            "rows_sha256": _sha256(rows_path),
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_paths: list[Path] = [chunk_path, rows_path]
    if edge_source_path is not None:
        _progress("read-edge-source", input=edge_source_path, limit=edge_limit)
        edge_sources = read_edge_reference_sources(edge_source_path, edge_limit)
        _progress("build-references", edges=len(edge_sources), nodes=len(rows))
        reference_chunk, reference_rows, reference_details = (
            build_graph_reference_chunk(rows, edge_sources)
        )
        reference_chunk_path = output / "graph_references.decoded.bin"
        reference_rows_path = output / "graph_references.rows.jsonl"
        reference_chunk_path.write_bytes(reference_chunk)
        with reference_rows_path.open("w", encoding="utf-8") as target:
            for row in reference_rows:
                target.write(
                    json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
                )
        manifest["graph_references"] = {
            **reference_details,
            "source": {
                "path": str(edge_source_path),
                "sha256": _sha256(edge_source_path),
                "records_consumed": len(edge_sources),
                "limit": edge_limit,
            },
            "binary": reference_chunk_path.name,
            "binary_sha256": _sha256(reference_chunk_path),
            "rows": reference_rows_path.name,
            "rows_sha256": _sha256(reference_rows_path),
        }
        manifest["writer_boundary"]["complete"].append(
            "direct EdgeRoadElement From/To global class handles"
        )
        integrated_chunk, node_bindings, integrated_edges, integrated_details = (
            build_integrated_graph_chunk(rows, edge_sources)
        )
        integrated_chunk_path = output / "integrated_graph.decoded.bin"
        integrated_nodes_path = output / "integrated_graph.nodes.jsonl"
        integrated_edges_path = output / "integrated_graph.edges.jsonl"
        integrated_chunk_path.write_bytes(integrated_chunk)
        with integrated_nodes_path.open("w", encoding="utf-8") as target:
            for row in node_bindings:
                target.write(
                    json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
                )
        with integrated_edges_path.open("w", encoding="utf-8") as target:
            for row in integrated_edges:
                target.write(
                    json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
                )
        manifest["integrated_graph"] = {
            **integrated_details,
            "binary": integrated_chunk_path.name,
            "binary_sha256": _sha256(integrated_chunk_path),
            "nodes": integrated_nodes_path.name,
            "nodes_sha256": _sha256(integrated_nodes_path),
            "edges": integrated_edges_path.name,
            "edges_sha256": _sha256(integrated_edges_path),
        }
        checksum_paths.extend(
            (integrated_chunk_path, integrated_nodes_path, integrated_edges_path)
        )
        manifest["writer_boundary"]["complete"].extend(
            [
                "implicit one-to-one EdgeRoadElement Attributes structure binding",
                "direct NodeRoadElement PointGeometry global handles",
                "NodeRoadElement Vias cardinality and flattened Edge handles",
                "integrated decoded graph chunk",
            ]
        )
        _progress(
            "integrated-graph-complete",
            chunk_bytes=len(integrated_chunk),
            point_handles=f"{integrated_details['point_geometry_handle_range'][0]}-{integrated_details['point_geometry_handle_range'][1]}",
            edge_handles=f"{integrated_details['edge_handle_range'][0]}-{integrated_details['edge_handle_range'][1]}",
            node_handles=f"{integrated_details['node_handle_range'][0]}-{integrated_details['node_handle_range'][1]}",
            vias=integrated_details["via_reference_count"],
            self_checks="all-pass",
        )
        checksum_paths.extend((reference_chunk_path, reference_rows_path))
        _progress(
            "references-complete",
            edges=len(edge_sources),
            node_handles=f"{reference_details['node_handle_range'][0]}-{reference_details['node_handle_range'][1]}",
            self_checks="all-pass",
        )
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_paths.append(manifest_path)
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{_sha256(path)}  {path.name}\n" for path in checksum_paths),
        encoding="ascii",
    )
    _progress(
        "complete",
        output=output,
        rows=len(rows),
        chunk_bytes=len(chunk),
        self_checks="all-pass",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="basic_graph_export nodes.jsonl")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--edges", type=Path, help="basic_graph_export edges.jsonl")
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="number of nodes to encode; 0 encodes the whole input",
    )
    parser.add_argument(
        "--edge-limit",
        type=int,
        default=0,
        help="number of edges to encode when --edges is set; 0 encodes all",
    )
    args = parser.parse_args()
    try:
        manifest = run(
            args.source, args.output, args.limit, args.edges, args.edge_limit
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"orion-object-writer error={error}", file=sys.stderr)
        return 1
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
