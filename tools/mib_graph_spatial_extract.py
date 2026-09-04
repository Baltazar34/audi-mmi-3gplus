#!/usr/bin/env python3
"""Extract a compact MIB Basic edge corpus intersecting a WGS84 bbox.

The full PSF index is split across local worker processes.  Only topology and
geometry and direct handle-2 semantic streams are decoded; matching edges retain
IDs, endpoints, vertices, names, raw endpoint class codes, road attributes, and
the firmware-backed Urban value.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
import struct
import sys
import unicodedata

from basic_geometry_decode import EDGE_DESCRIPTOR_STRIDE, _build_cluster, decode_geometry_record
from basic_graph_export import NODE_OFFSET_TABLE_BASE, _part_tagged_attributes
from basic_handle2_directory import decode_edge_directory, decode_record_data_end
from basic_handle2_text_decode import TextEntry, decode_direct_texts, schema_from_payload
from basic_name_semantics import LANGUAGE_LABELS, group_logical_names
from basic_road_attributes import (
    GeometryAttributeType,
    decode_automotive_attributes,
    decode_extended_passing_restriction_header,
    decode_extended_speed_limit,
    decode_number_of_lanes,
    decode_simple_speed_limit,
    decode_simple_passing_restriction,
    decode_travel_direction,
    decode_urban_road,
)
from basic_semantic_probe import topology_node_offsets
from psf_decode import _decode_indexed_lzma, _mercator_to_wgs84, read_basic_triple_handle_index
from basic_geometry_decode import _group_entries


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"mib-spatial-extract stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_name(value: str) -> str:
    decomposed = unicodedata.normalize("NFKD", value).casefold()
    return " ".join(
        "".join(
            ""
            if unicodedata.combining(character)
            else character
            if character.isalnum()
            else " "
            for character in decomposed
        )
        .split()
    )


def compact_semantic_names(entries: tuple[TextEntry, ...]) -> tuple[list[dict[str, object]], list[str]]:
    logical = group_logical_names(entries)
    names = [
        {
            "identifier": item.identifier,
            "language": LANGUAGE_LABELS.get(item.identifier),
            "base_values": list(item.base.primary),
            "transliteration_values": (
                list(item.transliteration.primary)
                if item.transliteration is not None
                else []
            ),
        }
        for item in logical
    ]
    normalized = sorted(
        {
            normalized
            for item in names
            for value in item["base_values"] + item["transliteration_values"]
            if (normalized := normalize_name(str(value)))
        }
    )
    return names, normalized


def worker(
    job: tuple[str, list[tuple[int, object]], tuple[float, float, float, float]],
) -> dict[str, object]:
    psf_name, clusters, bbox = job
    min_lon, min_lat, max_lon, max_lat = bbox
    rows: list[dict[str, object]] = []
    edge_count = 0
    with Path(psf_name).open("rb") as source:
        for cluster_id, handles in clusters:
            topology = _decode_indexed_lzma(source, handles[0])
            geometry_payload = _decode_indexed_lzma(source, handles[1])
            semantic_payload = _decode_indexed_lzma(source, handles[2])
            geometry = _build_cluster(cluster_id, topology, geometry_payload)
            node_offsets, _ = topology_node_offsets(topology, NODE_OFFSET_TABLE_BASE)
            semantic_directory = decode_edge_directory(
                semantic_payload, geometry.edge_count
            )
            semantic_data_end = decode_record_data_end(
                semantic_payload, semantic_directory.directory_end
            )
            semantic_offsets = sorted(set(semantic_directory.record_offsets))
            semantic_ends = {
                offset: (
                    semantic_offsets[index + 1]
                    if index + 1 < len(semantic_offsets)
                    else semantic_data_end
                )
                for index, offset in enumerate(semantic_offsets)
            }
            semantic_schema = schema_from_payload(semantic_payload)
            descriptor_end = (
                geometry.edge_descriptor_base
                + geometry.edge_count * EDGE_DESCRIPTOR_STRIDE
            )
            external_base = descriptor_end + (descriptor_end & 1)
            external_capacity = (node_offsets[0] - external_base) // 4

            def endpoint_id(edge_index: int, slot: int, mask: int) -> int:
                descriptor_at = (
                    geometry.edge_descriptor_base
                    + edge_index * EDGE_DESCRIPTOR_STRIDE
                )
                descriptor = topology[
                    descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
                ]
                encoded = descriptor[slot]
                if descriptor[4] & mask:
                    if encoded >= external_capacity:
                        raise ValueError("external endpoint index outside table")
                    return struct.unpack_from(
                        "<I", topology, external_base + encoded * 4
                    )[0]
                return (cluster_id << 8) | encoded

            for edge_index in range(geometry.edge_count):
                edge_count += 1
                parts = decode_geometry_record(geometry, edge_index)
                flat = []
                for part_index, part in enumerate(parts):
                    points = part.points if part_index == 0 else part.points[1:]
                    flat.extend(points)
                if len(flat) < 2:
                    continue
                wgs84 = [_mercator_to_wgs84(point.x, point.y) for point in flat]
                lon_values = [point[0] for point in wgs84]
                lat_values = [point[1] for point in wgs84]
                if (
                    max(lon_values) < min_lon
                    or min(lon_values) > max_lon
                    or max(lat_values) < min_lat
                    or min(lat_values) > max_lat
                ):
                    continue
                endpoint_a = endpoint_id(edge_index, 5, 0x40)
                endpoint_b = endpoint_id(edge_index, 6, 0x80)
                edge_id = (cluster_id << 8) | edge_index
                descriptor_at = (
                    geometry.edge_descriptor_base
                    + edge_index * EDGE_DESCRIPTOR_STRIDE
                )
                descriptor = topology[
                    descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
                ]
                direction = decode_travel_direction(descriptor)
                automotive = decode_automotive_attributes(descriptor)
                semantic_offset = semantic_directory.record_offsets[edge_index]
                semantic_entries = decode_direct_texts(
                    semantic_payload,
                    semantic_offset,
                    semantic_ends[semantic_offset],
                    semantic_schema,
                )
                logical_names, normalized_names = compact_semantic_names(
                    semantic_entries
                )

                def local_endpoint_class(slot: int, mask: int) -> int | None:
                    if descriptor[4] & mask:
                        return None
                    return topology[node_offsets[descriptor[slot]]] & 0x0F

                tagged = [
                    attribute
                    for part in parts
                    for attribute in _part_tagged_attributes(part)
                ]
                simple_speeds = [
                    decode_simple_speed_limit(attribute).value
                    for attribute in tagged
                    if attribute.type_id == 1
                ]
                extended_speeds = [
                    decode_extended_speed_limit(attribute)
                    for attribute in tagged
                    if attribute.type_id == GeometryAttributeType.EXTENDED_SPEED_LIMIT
                ]
                lane_counts = [
                    decode_number_of_lanes(attribute)
                    for attribute in tagged
                    if attribute.type_id == GeometryAttributeType.NUMBER_OF_LANES
                ]
                passing: list[dict[str, object]] = []
                for attribute in tagged:
                    if attribute.type_id == GeometryAttributeType.SIMPLE_PASSING_RESTRICTION:
                        decode_simple_passing_restriction(attribute)
                        passing.append({"kind": "simple"})
                    elif attribute.type_id == GeometryAttributeType.EXTENDED_PASSING_RESTRICTION:
                        value = decode_extended_passing_restriction_header(attribute)
                        passing.append(
                            {
                                "kind": "extended",
                                "a_to_b": value.a_to_b,
                                "b_to_a": value.b_to_a,
                                "has_detailed_records": value.has_detailed_records,
                                "detailed_record_count": value.detailed_record_count,
                            }
                        )
                rows.append(
                    {
                        "schema_version": 3,
                        "edge_id": edge_id,
                        "edge_id_hex": f"0x{edge_id:08x}",
                        "cluster_id": cluster_id,
                        "edge_index": edge_index,
                        "from_node_id": endpoint_a,
                        "to_node_id": endpoint_b,
                        "endpoint_class_codes": {
                            "from": local_endpoint_class(5, 0x40),
                            "to": local_endpoint_class(6, 0x80),
                            "source": (
                                "local node-record low nibble; firmware VA 0x0154faec; "
                                "external endpoint left null"
                            ),
                        },
                        "logical_names": logical_names,
                        "normalized_names": normalized_names,
                        "centerline": [
                            {
                                "longitude": lon,
                                "latitude": lat,
                                "mercator": [point.x, point.y],
                            }
                            for point, (lon, lat) in zip(flat, wgs84)
                        ],
                        "bbox": [
                            min(lon_values),
                            min(lat_values),
                            max(lon_values),
                            max(lat_values),
                        ],
                        "geometry_part_secondary_flags": [
                            part.secondary_flags for part in parts
                        ],
                        "urban": decode_urban_road(
                            part.secondary_flags for part in parts
                        ),
                        "travel_direction": {
                            "mode": direction.mode,
                            "a_to_b_allowed": direction.a_to_b_allowed,
                            "b_to_a_allowed": direction.b_to_a_allowed,
                        },
                        "automotive": {
                            "base_mask": automotive.base_mask,
                            "active_bit_indices": list(automotive.active_bit_indices),
                            "has_dynamic_extension": automotive.has_dynamic_extension,
                        },
                        "geometry_attribute_type_ids": sorted(
                            {int(attribute.type_id) for attribute in tagged}
                        ),
                        "simple_speed_limit_values": sorted(set(simple_speeds)),
                        "speed_limits": [
                            {"kind": "simple", "value": value}
                            for value in sorted(set(simple_speeds))
                        ]
                        + [
                            {
                                "kind": "extended",
                                "value": value.value,
                                "a_to_b": value.a_to_b,
                                "b_to_a": value.b_to_a,
                                "subtype": value.subtype,
                                "base_condition": value.base_condition,
                                "condition_pairs": [list(pair) for pair in value.condition_pairs],
                                "source_selector": value.source_selector,
                            }
                            for value in extended_speeds
                        ],
                        "number_of_lanes": [
                            {"at_node_a": value.at_node_a, "at_node_b": value.at_node_b}
                            for value in lane_counts
                        ],
                        "passing_restrictions": passing,
                        "has_number_of_lanes": any(
                            attribute.type_id == GeometryAttributeType.NUMBER_OF_LANES
                            for attribute in tagged
                        ),
                        "has_passing_restriction": any(
                            attribute.type_id
                            in {
                                GeometryAttributeType.SIMPLE_PASSING_RESTRICTION,
                                GeometryAttributeType.EXTENDED_PASSING_RESTRICTION,
                            }
                            for attribute in tagged
                        ),
                    }
                )
    return {"clusters": len(clusters), "edges_scanned": edge_count, "rows": rows}


def run(
    psf: Path,
    output: Path,
    bbox: tuple[float, float, float, float],
    jobs: int,
) -> dict[str, object]:
    if not 1 <= jobs <= 64:
        raise ValueError("jobs must be between 1 and 64")
    min_lon, min_lat, max_lon, max_lat = bbox
    if not (min_lon < max_lon and min_lat < max_lat):
        raise ValueError("invalid bbox")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    assignments: list[list[tuple[int, object]]] = [[] for _ in range(jobs)]
    for ordinal, cluster_id in enumerate(order):
        assignments[ordinal % jobs].append((cluster_id, grouped[cluster_id]))
    work = [
        (str(psf), assignment, bbox)
        for assignment in assignments
        if assignment
    ]
    progress("start", clusters=len(order), jobs=len(work), bbox=",".join(map(str, bbox)))
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        results = list(pool.map(worker, work))
    rows = [row for result in results for row in result["rows"]]
    rows.sort(key=lambda row: int(row["edge_id"]))
    edge_ids = [int(row["edge_id"]) for row in rows]
    checks = {
        "all_clusters_scanned": sum(int(row["clusters"]) for row in results)
        == len(order),
        "edge_count_matches_known_corpus": sum(
            int(row["edges_scanned"]) for row in results
        )
        == 838_433,
        "matching_edge_ids_unique": len(edge_ids) == len(set(edge_ids)),
        "all_matching_bboxes_intersect_query": all(
            not (
                row["bbox"][2] < min_lon
                or row["bbox"][0] > max_lon
                or row["bbox"][3] < min_lat
                or row["bbox"][1] > max_lat
            )
            for row in rows
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"spatial extract checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    edges_path = output / "edges.jsonl"
    report_path = output / "report.json"
    edges_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = {
        "schema_version": 3,
        "status": "complete",
        "input": str(psf),
        "bbox": list(bbox),
        "jobs": jobs,
        "clusters": len(order),
        "edges_scanned": sum(int(row["edges_scanned"]) for row in results),
        "matching_edges": len(rows),
        "urban_matching_edges": sum(bool(row["urban"]) for row in rows),
        "matching_edges_with_names": sum(bool(row["normalized_names"]) for row in rows),
        "normalized_name_references": sum(len(row["normalized_names"]) for row in rows),
        "local_endpoint_class_values": sum(
            value is not None
            for row in rows
            for value in row["endpoint_class_codes"].values()
            if not isinstance(value, str)
        ),
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
    progress(
        "complete",
        edges_scanned=report["edges_scanned"],
        matching_edges=len(rows),
        checks="all-pass",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--bbox",
        type=float,
        nargs=4,
        required=True,
        metavar=("MIN_LON", "MIN_LAT", "MAX_LON", "MAX_LAT"),
    )
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    try:
        report = run(args.psf, args.output, tuple(args.bbox), args.jobs)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"mib-spatial-extract error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
