#!/usr/bin/env python3
"""Reconstruct original Orion edge endpoints and geometry provenance.

The input directory must be a saved corpus from ``orion_graph_spatial_probe``.
For every original EdgeRoadElement row this tool resolves From/To global
handles through NodeRoadElement and PointGeometry to the row-aligned PointLlh
coordinate.  CenterlineGeometry is intentionally retained as a typed global
handle; decoding its Parts/PointLld payload is the next, separate stage.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from orion_column_codec import validate_code1_payload_roundtrip
from orion_property_corpus_profile import _composite, _decode_part, _derives_from, _group
from orion_psd_reference_profile import class_object_ranges, group_serialized_parts


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-edge-geometry stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def named_class_ranges(schema: dict[str, object]) -> dict[str, tuple[int, int]]:
    ranges = class_object_ranges(schema)
    return {
        str(row["name"]): ranges[int(row["index"])]
        for row in schema["composites"]
        if int(row["kind"]) == 1
    }


def classify(handle: int, ranges: dict[str, tuple[int, int]]) -> str:
    for name, (first, last) in ranges.items():
        if first <= handle <= last:
            return name
    return "INVALID"


def load_properties(path: Path) -> dict[tuple[int, int], dict[str, object]]:
    rows: dict[tuple[int, int], dict[str, object]] = {}
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            row = json.loads(line)
            key = (int(row["block_offset"]), int(row["edge_row"]))
            if key in rows:
                raise ValueError(f"duplicate property key {key} at line {line_number}")
            rows[key] = row
    return rows


def decode_sample(
    schema_path: Path,
    properties: dict[tuple[int, int], dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, object], set[tuple[int, int]]]:
    metadata = json.loads(schema_path.read_text(encoding="utf-8"))
    decoded_path = schema_path.with_name(
        schema_path.name.replace(".schema.json", ".decoded.bin")
    )
    decoded = decoded_path.read_bytes()
    schema = metadata["schema"]
    table = metadata["table"]
    if any(int(code) != 1 for code in table["compression_codes"]):
        raise ValueError(f"{schema_path.name} contains a non-code-1 column")
    groups = group_serialized_parts(schema, table["descriptors"])
    layouts = validate_code1_payload_roundtrip(
        decoded,
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )

    point_llh = _composite(schema, "PointLlh")
    point_geometry = _composite(schema, "PointGeometry")
    edge = _composite(schema, "EdgeRoadElement")
    node = _composite(schema, "NodeRoadElement")
    point_count = int(point_llh["row_count"])
    if int(point_geometry["row_count"]) != point_count:
        raise ValueError("PointGeometry and PointLlh row counts differ")
    node_count = int(node["row_count"])
    if node_count != point_count:
        raise ValueError("NodeRoadElement and PointLlh row counts differ")
    edge_count = int(edge["row_count"])

    def direct(composite: str, member: str, count: int) -> tuple[list[int], int]:
        group = _group(groups, composite, member)
        if int(group["part_count"]) != 1:
            raise ValueError(f"{composite}.{member} is not one direct column")
        part = int(group["part_start"])
        return _decode_part(decoded, table, layouts, part, count), part

    longitudes, longitude_part = direct("PointLlh", "Longitude", point_count)
    latitudes, latitude_part = direct("PointLlh", "Latitude", point_count)
    node_points, node_point_part = direct(
        "NodeRoadElement", "PointGeometry", node_count
    )
    centerlines, centerline_part = direct(
        "EdgeRoadElement", "CenterlineGeometry", edge_count
    )
    from_handles, from_part = direct("EdgeRoadElement", "From", edge_count)
    to_handles, to_part = direct("EdgeRoadElement", "To", edge_count)

    ranges = named_class_ranges(schema)
    point_first, point_last = ranges["PointGeometry"]
    node_first, node_last = ranges["NodeRoadElement"]
    if sorted(node_points) != list(range(point_first, point_last + 1)):
        raise ValueError("Node.PointGeometry is not a permutation of PointGeometry")

    by_index = {int(row["index"]): row for row in schema["composites"]}
    centerline_base = _composite(schema, "CenterlineGeometry")
    centerline_base_index = int(centerline_base["index"])
    centerline_ranges = {
        str(row["name"]): ranges[str(row["name"])]
        for row in schema["composites"]
        if int(row["kind"]) == 1
        and int(row["index"]) != centerline_base_index
        and _derives_from(row, centerline_base_index, by_index)
    }
    if not centerline_ranges:
        raise ValueError("no concrete CenterlineGeometry subclass range")

    used_property_keys: set[tuple[int, int]] = set()
    centerline_classes: Counter[str] = Counter()
    external_endpoints = 0
    rows: list[dict[str, object]] = []
    block_offset = int(metadata["block_offset"])

    def endpoint(handle: int) -> dict[str, object] | None:
        nonlocal external_endpoints
        if handle == 0:
            external_endpoints += 1
            return None
        if not node_first <= handle <= node_last:
            raise ValueError(f"endpoint handle {handle} outside NodeRoadElement")
        node_row = handle - node_first
        point_handle = node_points[node_row]
        if not point_first <= point_handle <= point_last:
            raise ValueError(f"point handle {point_handle} outside PointGeometry")
        point_row = point_handle - point_first
        return {
            "node_handle": handle,
            "node_row": node_row,
            "point_geometry_handle": point_handle,
            "point_geometry_row": point_row,
            "point_llh_row": point_row,
            "longitude_e7": longitudes[point_row],
            "latitude_e7": latitudes[point_row],
            "longitude": longitudes[point_row] / 10_000_000,
            "latitude": latitudes[point_row] / 10_000_000,
        }

    for edge_row, (centerline_handle, from_handle, to_handle) in enumerate(
        zip(centerlines, from_handles, to_handles)
    ):
        centerline_class = classify(centerline_handle, centerline_ranges)
        if centerline_class == "INVALID":
            raise ValueError(
                f"centerline handle {centerline_handle} outside concrete subclasses"
            )
        centerline_classes[centerline_class] += 1
        property_key = (block_offset, edge_row)
        if property_key not in properties:
            raise ValueError(f"missing property row for {property_key}")
        property_row = properties[property_key]
        used_property_keys.add(property_key)
        rows.append(
            {
                "source_schema": schema_path.name,
                "block_offset": block_offset,
                "block_offset_hex": metadata["block_offset_hex"],
                "edge_row": edge_row,
                "centerline_geometry": {
                    "handle": centerline_handle,
                    "class": centerline_class,
                    "class_row": centerline_handle
                    - centerline_ranges[centerline_class][0],
                },
                "from": endpoint(from_handle),
                "to": endpoint(to_handle),
                "properties": {
                    "attribute_part_count": property_row["attribute_part_count"],
                    "property_lists": property_row["property_lists"],
                    "baseline_tuples": property_row["baseline_tuples"],
                    "effective_baseline_tuple_or": property_row[
                        "effective_baseline_tuple_or"
                    ],
                },
            }
        )

    summary = {
        "schema": schema_path.name,
        "decoded": decoded_path.name,
        "block_offset": block_offset,
        "block_offset_hex": metadata["block_offset_hex"],
        "edges": edge_count,
        "nodes": node_count,
        "points": point_count,
        "external_endpoint_sentinels": external_endpoints,
        "centerline_classes": dict(sorted(centerline_classes.items())),
        "descriptor_parts": {
            "PointLlh.Longitude": longitude_part,
            "PointLlh.Latitude": latitude_part,
            "NodeRoadElement.PointGeometry": node_point_part,
            "EdgeRoadElement.CenterlineGeometry": centerline_part,
            "EdgeRoadElement.From": from_part,
            "EdgeRoadElement.To": to_part,
        },
        "checks": {
            "point_geometry_point_llh_row_alignment": True,
            "node_point_handles_are_complete_permutation": True,
            "all_nonzero_endpoints_in_node_range": True,
            "all_centerlines_in_concrete_subclass_ranges": True,
            "properties_joined_one_to_one": len(used_property_keys) == edge_count,
        },
    }
    return rows, summary, used_property_keys


def run(input_dir: Path, property_path: Path, output: Path) -> dict[str, object]:
    schema_paths = sorted(input_dir.glob("match_*.schema.json"))
    if not schema_paths:
        raise ValueError(f"no match_*.schema.json files in {input_dir}")
    properties = load_properties(property_path)
    output.mkdir(parents=True, exist_ok=True)
    edges_path = output / "edges.source.jsonl"
    report_path = output / "report.json"
    all_rows: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    used_keys: set[tuple[int, int]] = set()
    global_classes: Counter[str] = Counter()
    for schema_path in schema_paths:
        rows, summary, chunk_keys = decode_sample(schema_path, properties)
        if used_keys & chunk_keys:
            raise ValueError("property keys reused across chunks")
        used_keys.update(chunk_keys)
        all_rows.extend(rows)
        summaries.append(summary)
        global_classes.update(summary["centerline_classes"])
        progress(
            "chunk",
            block=summary["block_offset_hex"],
            edges=summary["edges"],
            nodes=summary["nodes"],
            external=summary["external_endpoint_sentinels"],
        )
    checks = {
        "all_chunks_decoded": len(summaries) == len(schema_paths),
        "edge_count_matches_property_rows": len(all_rows) == len(properties),
        "every_property_row_consumed": used_keys == set(properties),
        "all_chunk_checks_pass": all(
            all(bool(value) for value in summary["checks"].values())
            for summary in summaries
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"global edge geometry checks failed: {checks}")
    edges_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in all_rows),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "scope": "endpoint topology and typed centerline provenance",
        "input": str(input_dir),
        "property_input": str(property_path),
        "chunks": len(summaries),
        "edges": len(all_rows),
        "nodes": sum(int(row["nodes"]) for row in summaries),
        "points": sum(int(row["points"]) for row in summaries),
        "external_endpoint_sentinels": sum(
            int(row["external_endpoint_sentinels"]) for row in summaries
        ),
        "centerline_classes": dict(sorted(global_classes.items())),
        "coordinate_encoding": "signed degree * 1e7",
        "centerline_payload_status": "not decoded in this stage",
        "chunk_summaries": summaries,
        "checks": checks,
        "artifacts": {"edges": edges_path.name},
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        f"{sha256(edges_path)}  {edges_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    progress("complete", chunks=len(summaries), edges=len(all_rows), checks="all-pass")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("--properties", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.input_dir, args.properties, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-edge-geometry error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
