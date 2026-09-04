#!/usr/bin/env python3
"""Profile original Orion Item.Identifiers without assuming edge-ID semantics."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import struct
import sys

from orion_column_codec import validate_code1_payload_roundtrip
from orion_property_corpus_profile import _composite, _derives_from
from orion_psd_reference_profile import group_serialized_parts


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def edge_points(row: dict[str, object]) -> list[tuple[float, float]]:
    return [
        (float(point["longitude"]), float(point["latitude"]))
        for part in row["centerline_geometry"]["parts"]
        for point in part["positions"]
    ]


def metres(left: tuple[float, float], right: tuple[float, float]) -> float:
    latitude = math.radians((left[1] + right[1]) / 2)
    dx = (left[0] - right[0]) * 111_320 * math.cos(latitude)
    dy = (left[1] - right[1]) * 110_540
    return math.hypot(dx, dy)


def geometry_relation(
    left: list[tuple[float, float]], right: list[tuple[float, float]]
) -> str:
    if left == right:
        return "exact"
    if left == list(reversed(right)):
        return "reversed"
    return "different"


def run(
    probe_dirs: list[Path], centerline_paths: list[Path], output: Path
) -> dict[str, object]:
    if len(probe_dirs) != len(centerline_paths):
        raise ValueError("--probe and --centerlines counts differ")
    geometries: dict[tuple[int, int], list[tuple[float, float]]] = {}
    for path in centerline_paths:
        for row in read_jsonl(path):
            geometries[(int(row["block_offset"]), int(row["edge_row"]))] = edge_points(row)
    rows: list[dict[str, object]] = []
    chunk_count = 0
    for probe in probe_dirs:
        for schema_path in sorted(probe.glob("match_*.schema.json")):
            metadata = json.loads(schema_path.read_text(encoding="utf-8"))
            schema = metadata["schema"]
            table = metadata["table"]
            decoded_path = schema_path.with_name(
                schema_path.name.replace(".schema.json", ".decoded.bin")
            )
            decoded = decoded_path.read_bytes()
            layouts = validate_code1_payload_roundtrip(
                decoded,
                int(schema["data_offset"]),
                table["descriptors"],
                table["compression_codes"],
            )
            groups = group_serialized_parts(schema, table["descriptors"])
            item = _composite(schema, "Item")
            item_index = int(item["index"])
            by_index = {int(row["index"]): row for row in schema["composites"]}
            concrete = [
                row
                for row in schema["composites"]
                if int(row["kind"]) == 1
                and int(row["index"]) != item_index
                and int(row["row_count"]) > 0
                and _derives_from(row, item_index, by_index)
            ]
            group = next(
                row
                for row in groups
                if row["composite_name"] == "Item"
                and row["member_name"] == "Identifiers"
            )
            if int(group["part_count"]) != 1:
                raise ValueError("Item.Identifiers is not one physical part")
            descriptor_index = int(group["part_start"])
            descriptor = table["descriptors"][descriptor_index]
            if int(descriptor["tag"]) != 2 or int(descriptor["type_code"]) != 0x26:
                raise ValueError("unexpected Item.Identifiers descriptor")
            layout = layouts[descriptor_index]
            payload = decoded[
                layout.payload_offset : layout.payload_offset + layout.payload_size
            ]
            expected_rows = sum(int(row["row_count"]) for row in concrete)
            if len(payload) != expected_rows * 8:
                raise ValueError("Item.Identifiers payload does not cover derived rows")
            cursor = 0
            for composite in concrete:
                class_name = str(composite["name"])
                for class_row in range(int(composite["row_count"])):
                    low, high = struct.unpack_from("<II", payload, cursor * 8)
                    record: dict[str, object] = {
                        "block_offset": int(metadata["block_offset"]),
                        "block_offset_hex": metadata["block_offset_hex"],
                        "class": class_name,
                        "class_row": class_row,
                        "identifier_u64": (high << 32) | low,
                        "identifier_hex": f"0x{high:08x}{low:08x}",
                        "low_u32": low,
                        "high_u32": high,
                    }
                    if class_name == "EdgeRoadElement":
                        record["edge_key"] = [int(metadata["block_offset"]), class_row]
                    rows.append(record)
                    cursor += 1
            chunk_count += 1
    by_identifier: dict[int, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_identifier[int(row["identifier_u64"])].append(row)
    duplicate_class_patterns = Counter()
    geometry_relations = Counter()
    endpoint_bins = Counter()
    duplicate_groups: list[dict[str, object]] = []
    for identifier, members in by_identifier.items():
        if len(members) < 2:
            continue
        duplicate_class_patterns["+".join(sorted(str(row["class"]) for row in members))] += 1
        edge_members = [row for row in members if row["class"] == "EdgeRoadElement"]
        pair_distances: list[float] = []
        for index, left in enumerate(edge_members):
            left_key = tuple(left["edge_key"])
            left_geometry = geometries[left_key]
            for right in edge_members[index + 1 :]:
                right_key = tuple(right["edge_key"])
                right_geometry = geometries[right_key]
                relation = geometry_relation(left_geometry, right_geometry)
                geometry_relations[relation] += 1
                distance = min(
                    metres(a, b)
                    for a in (left_geometry[0], left_geometry[-1])
                    for b in (right_geometry[0], right_geometry[-1])
                )
                pair_distances.append(distance)
                endpoint_bins[
                    "<=10m"
                    if distance <= 10
                    else "<=50m"
                    if distance <= 50
                    else "<=250m"
                    if distance <= 250
                    else "<=1000m"
                    if distance <= 1000
                    else ">1000m"
                ] += 1
        duplicate_groups.append(
            {
                "identifier_u64": identifier,
                "identifier_hex": f"0x{identifier:016x}",
                "members": [
                    {
                        "block_offset": row["block_offset"],
                        "class": row["class"],
                        "class_row": row["class_row"],
                    }
                    for row in members
                ],
                "minimum_edge_endpoint_distance_metres": (
                    min(pair_distances) if pair_distances else None
                ),
            }
        )
    u64_counts = Counter(int(row["identifier_u64"]) for row in rows)
    low_counts = Counter(int(row["low_u32"]) for row in rows)
    high_counts = Counter(int(row["high_u32"]) for row in rows)
    edge_rows = [row for row in rows if row["class"] == "EdgeRoadElement"]
    checks = {
        "all_identifier_payloads_cover_derived_item_rows": True,
        "every_edge_identifier_has_centerline": all(
            tuple(row["edge_key"]) in geometries for row in edge_rows
        ),
        "no_identifier_repeats_inside_one_chunk": all(
            len({int(row["block_offset"]) for row in members}) == len(members)
            for members in by_identifier.values()
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"Item identifier checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    rows_path = output / "identifiers.jsonl"
    duplicates_path = output / "duplicate_groups.jsonl"
    report_path = output / "report.json"
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    duplicates_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in duplicate_groups),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "chunks": chunk_count,
        "identifier_rows": len(rows),
        "edge_identifier_rows": len(edge_rows),
        "u64_unique": len(u64_counts),
        "u64_duplicate_values": sum(count > 1 for count in u64_counts.values()),
        "u64_duplicate_rows": sum(count - 1 for count in u64_counts.values()),
        "low_u32_unique": len(low_counts),
        "high_u32_unique": len(high_counts),
        "duplicate_class_patterns": dict(sorted(duplicate_class_patterns.items())),
        "duplicate_edge_geometry_relations": dict(sorted(geometry_relations.items())),
        "duplicate_edge_minimum_endpoint_distance_bins": dict(sorted(endpoint_bins.items())),
        "interpretation": (
            "Item.Identifiers is an exact 64-bit source field over class-ordered Item-derived "
            "rows, but repeated values do not reproduce the same edge geometry. It must not be "
            "used as a unique edge identity key; road-group/name-key semantics remain possible."
        ),
        "checks": checks,
        "artifacts": {
            "identifiers": rows_path.name,
            "duplicate_groups": duplicates_path.name,
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(rows_path)}  {rows_path.name}\n"
        f"{sha256(duplicates_path)}  {duplicates_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    print(
        f"orion-item-identifiers chunks={chunk_count} rows={len(rows)} "
        f"duplicates={report['u64_duplicate_values']} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, action="append", required=True)
    parser.add_argument("--centerlines", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.probe, args.centerlines, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-item-identifiers error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
