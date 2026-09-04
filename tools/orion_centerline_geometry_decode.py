#!/usr/bin/env python3
"""Decode original Orion clothoid Parts and PointLld rows per edge.

Chunks are independent and are decoded in a local process pool.  The output
preserves every original part, point coordinate, and direction value without
fitting or simplifying geometry.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import sys

from orion_column_codec import validate_code1_payload_roundtrip
from orion_property_corpus_profile import _composite, _decode_part, _group
from orion_psd_reference_profile import group_serialized_parts


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-centerline-decode stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def distance_metres(a: dict[str, object], b: dict[str, object]) -> float:
    latitude = math.radians((float(a["latitude"]) + float(b["latitude"])) / 2)
    dx = math.radians(float(a["longitude"]) - float(b["longitude"]))
    dy = math.radians(float(a["latitude"]) - float(b["latitude"]))
    return 6_371_008.8 * math.hypot(dx * math.cos(latitude), dy)


def load_edge_source(path: Path) -> dict[tuple[int, int], dict[str, object]]:
    rows: dict[tuple[int, int], dict[str, object]] = {}
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            row = json.loads(line)
            key = (int(row["block_offset"]), int(row["edge_row"]))
            if key in rows:
                raise ValueError(f"duplicate edge key {key} at line {line_number}")
            rows[key] = row
    return rows


def decode_chunk(job: tuple[str, list[dict[str, object]]]) -> dict[str, object]:
    schema_name, edge_rows = job
    schema_path = Path(schema_name)
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

    point = _composite(schema, "PointLld")
    part = _composite(schema, "ClothoidCenterlineGeometryPart")
    centerline = _composite(schema, "ClothoidCenterlineGeometry")
    point_count = int(point["row_count"])
    part_count = int(part["row_count"])
    centerline_count = int(centerline["row_count"])
    if len(edge_rows) != centerline_count:
        raise ValueError(
            f"{schema_path.name}: {len(edge_rows)} edges != {centerline_count} centerlines"
        )

    def direct(composite: str, member: str, count: int) -> tuple[list[int], int]:
        group = _group(groups, composite, member)
        if int(group["part_count"]) != 1:
            raise ValueError(f"{composite}.{member} is not one direct column")
        index = int(group["part_start"])
        return _decode_part(decoded, table, layouts, index, count), index

    longitudes, longitude_part = direct("PointLld", "Longitude", point_count)
    latitudes, latitude_part = direct("PointLld", "Latitude", point_count)
    directions, direction_part = direct("PointLld", "Direction", point_count)
    positions_per_part, positions_part = direct(
        "ClothoidCenterlineGeometryPart", "Positions", part_count
    )
    parts_per_centerline, centerline_parts_part = direct(
        "ClothoidCenterlineGeometry", "Parts", centerline_count
    )
    if sum(positions_per_part) != point_count:
        raise ValueError("Positions cardinalities do not cover PointLld rows")
    if sum(parts_per_centerline) != part_count:
        raise ValueError("Parts cardinalities do not cover centerline-part rows")
    if any(value < 2 for value in positions_per_part):
        raise ValueError("clothoid part contains fewer than two PointLld rows")
    if any(value < 1 for value in parts_per_centerline):
        raise ValueError("centerline contains no parts")
    if not all(-1800000000 <= lon <= 1800000000 for lon in longitudes):
        raise ValueError("PointLld longitude outside degree-e7 range")
    if not all(-900000000 <= lat <= 900000000 for lat in latitudes):
        raise ValueError("PointLld latitude outside degree-e7 range")
    if not all(0 <= direction <= 0xFFFF for direction in directions):
        raise ValueError("PointLld direction outside unsigned full-circle range")

    parts: list[dict[str, object]] = []
    point_cursor = 0
    for part_row, cardinality in enumerate(positions_per_part):
        points: list[dict[str, object]] = []
        for point_row in range(point_cursor, point_cursor + cardinality):
            points.append(
                {
                    "point_lld_row": point_row,
                    "longitude_e7": longitudes[point_row],
                    "latitude_e7": latitudes[point_row],
                    "longitude": longitudes[point_row] / 10_000_000,
                    "latitude": latitudes[point_row] / 10_000_000,
                    "direction_u16": directions[point_row],
                }
            )
        point_cursor += cardinality
        parts.append(
            {
                "part_row": part_row,
                "position_count": cardinality,
                "positions": points,
            }
        )

    centerline_parts: list[list[dict[str, object]]] = []
    part_cursor = 0
    for cardinality in parts_per_centerline:
        centerline_parts.append(parts[part_cursor : part_cursor + cardinality])
        part_cursor += cardinality

    ordered_edges = sorted(edge_rows, key=lambda row: int(row["edge_row"]))
    class_rows = [
        int(row["centerline_geometry"]["class_row"]) for row in ordered_edges
    ]
    if sorted(class_rows) != list(range(centerline_count)):
        raise ValueError("edge centerline handles are not a complete permutation")

    output_rows: list[dict[str, object]] = []
    endpoint_modes: Counter[str] = Counter()
    endpoint_errors: list[float] = []
    for edge_row, class_row in zip(ordered_edges, class_rows):
        edge_parts = centerline_parts[class_row]
        cardinality = len(edge_parts)
        first_point = edge_parts[0]["positions"][0]
        last_point = edge_parts[-1]["positions"][-1]
        endpoint_check: dict[str, object] | None = None
        from_endpoint = edge_row["from"]
        to_endpoint = edge_row["to"]
        if from_endpoint is not None and to_endpoint is not None:
            forward = max(
                distance_metres(first_point, from_endpoint),
                distance_metres(last_point, to_endpoint),
            )
            reverse = max(
                distance_metres(first_point, to_endpoint),
                distance_metres(last_point, from_endpoint),
            )
            mode = "forward" if forward <= reverse else "reverse"
            error = min(forward, reverse)
            endpoint_modes[mode] += 1
            endpoint_errors.append(error)
            endpoint_check = {
                "orientation": mode,
                "maximum_endpoint_error_metres": round(error, 6),
            }
        output_rows.append(
            {
                **edge_row,
                "centerline_geometry": {
                    **edge_row["centerline_geometry"],
                    "part_count": cardinality,
                    "parts": edge_parts,
                    "endpoint_check": endpoint_check,
                },
            }
        )

    return {
        "rows": output_rows,
        "summary": {
            "schema": schema_path.name,
            "block_offset": metadata["block_offset"],
            "block_offset_hex": metadata["block_offset_hex"],
            "edges": centerline_count,
            "parts": part_count,
            "point_lld_rows": point_count,
            "minimum_positions_per_part": min(positions_per_part),
            "maximum_positions_per_part": max(positions_per_part),
            "minimum_parts_per_edge": min(parts_per_centerline),
            "maximum_parts_per_edge": max(parts_per_centerline),
            "endpoint_orientations": dict(sorted(endpoint_modes.items())),
            "maximum_endpoint_error_metres": (
                max(endpoint_errors) if endpoint_errors else None
            ),
            "descriptor_parts": {
                "PointLld.Longitude": longitude_part,
                "PointLld.Latitude": latitude_part,
                "PointLld.Direction": direction_part,
                "ClothoidCenterlineGeometryPart.Positions": positions_part,
                "ClothoidCenterlineGeometry.Parts": centerline_parts_part,
            },
            "checks": {
                "positions_cover_all_point_lld_rows": True,
                "parts_cover_all_part_rows": True,
                "every_part_has_at_least_two_positions": True,
                "every_centerline_has_at_least_one_part": True,
                "coordinates_and_directions_in_range": True,
                "edge_centerlines_are_complete_permutation": True,
            },
        },
    }


def run(
    input_dir: Path,
    edge_source_path: Path,
    output: Path,
    jobs: int,
) -> dict[str, object]:
    if not 1 <= jobs <= 64:
        raise ValueError("jobs must be between 1 and 64")
    schema_paths = sorted(input_dir.glob("match_*.schema.json"))
    if not schema_paths:
        raise ValueError(f"no match_*.schema.json files in {input_dir}")
    edge_source = load_edge_source(edge_source_path)
    grouped: dict[str, list[dict[str, object]]] = {
        path.name: [] for path in schema_paths
    }
    for row in edge_source.values():
        name = str(row["source_schema"])
        if name not in grouped:
            raise ValueError(f"edge references unknown schema {name}")
        grouped[name].append(row)
    work = [(str(path), grouped[path.name]) for path in schema_paths]
    progress("start", chunks=len(work), edges=len(edge_source), jobs=jobs)
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        decoded_chunks = list(pool.map(decode_chunk, work))
    decoded_chunks.sort(key=lambda item: int(item["summary"]["block_offset"]))

    rows: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    orientations: Counter[str] = Counter()
    for item in decoded_chunks:
        summary = item["summary"]
        summaries.append(summary)
        rows.extend(item["rows"])
        orientations.update(summary["endpoint_orientations"])
        progress(
            "chunk",
            block=summary["block_offset_hex"],
            edges=summary["edges"],
            parts=summary["parts"],
            points=summary["point_lld_rows"],
        )
    keys = [(int(row["block_offset"]), int(row["edge_row"])) for row in rows]
    checks = {
        "all_chunks_decoded": len(summaries) == len(schema_paths),
        "edge_count_preserved": len(rows) == len(edge_source),
        "edge_keys_preserved_exactly_once": len(keys) == len(set(keys))
        and set(keys) == set(edge_source),
        "all_chunk_checks_pass": all(
            all(bool(value) for value in summary["checks"].values())
            for summary in summaries
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"centerline global checks failed: {checks}")

    output.mkdir(parents=True, exist_ok=True)
    edges_path = output / "edges.centerlines.jsonl"
    report_path = output / "report.json"
    edges_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "scope": "lossless original ClothoidCenterlineGeometry Parts and PointLld",
        "input": str(input_dir),
        "edge_source_input": str(edge_source_path),
        "jobs": jobs,
        "chunks": len(summaries),
        "edges": len(rows),
        "parts": sum(int(row["parts"]) for row in summaries),
        "point_lld_rows": sum(int(row["point_lld_rows"]) for row in summaries),
        "endpoint_orientations": dict(sorted(orientations.items())),
        "maximum_endpoint_error_metres": max(
            float(row["maximum_endpoint_error_metres"] or 0) for row in summaries
        ),
        "coordinate_encoding": "signed degree * 1e7",
        "direction_encoding": "unsigned full circle / 65536",
        "chunk_summaries": summaries,
        "checks": checks,
        "artifacts": {"edges": edges_path.name},
        "next_boundary": "Spatially match decoded original polylines to MIB edge geometry.",
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
        edges=len(rows),
        parts=report["parts"],
        points=report["point_lld_rows"],
        checks="all-pass",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("--edge-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    try:
        report = run(args.input_dir, args.edge_source, args.output, args.jobs)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-centerline-decode error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
