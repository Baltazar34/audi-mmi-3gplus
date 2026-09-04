#!/usr/bin/env python3
"""Locate original Orion graph chunks intersecting a longitude/latitude box.

The probe is intentionally read-only.  It decodes only enough of each graph
chunk to recover PointLlh Longitude/Latitude columns, making it suitable for
selecting a small geographic corpus before full object reconstruction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import math
from pathlib import Path
import struct
import sys
import zlib

from orion_column_codec import code1_column_layout, type_widths, unpack_code1_values
from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    _read_name,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
)


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-spatial-probe stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def schema_names(schema: dict[str, object]) -> set[str]:
    names = {str(schema["map_name"])}
    for composite in schema["composites"]:
        names.add(str(composite["name"]))
        names.update(
            str(member["name"])
            for member in composite["members"]
            if member.get("name") is not None
        )
    return names


def point_columns(
    decoded: bytes,
    schema: dict[str, object],
    table: dict[str, object],
) -> tuple[list[int], list[int]] | None:
    """Return original degree*1e7 PointLlh columns when directly code-1 backed."""

    groups = group_serialized_parts(schema, table["descriptors"])
    layouts = code1_column_layout(
        len(decoded),
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    composites = {
        int(composite["index"]): composite for composite in schema["composites"]
    }
    wanted: dict[str, list[int]] = {}
    for group in groups:
        composite = composites[int(group["composite_index"])]
        if composite["name"] != "PointLlh" or int(group["part_count"]) != 1:
            continue
        member_name = str(group["member_name"])
        if member_name not in {"Longitude", "Latitude"}:
            continue
        row_count = int(composite["row_count"])
        layout = layouts[int(group["part_start"])]
        _, storage_bits = type_widths(layout.type_code)
        if layout.payload_size != (row_count * storage_bits + 7) // 8:
            continue
        payload = decoded[
            layout.payload_offset : layout.payload_offset + layout.payload_size
        ]
        wanted[member_name] = unpack_code1_values(
            layout.type_code, payload, row_count
        )
    if set(wanted) != {"Longitude", "Latitude"}:
        return None
    if len(wanted["Longitude"]) != len(wanted["Latitude"]):
        raise ValueError("PointLlh longitude/latitude row count mismatch")
    return wanted["Longitude"], wanted["Latitude"]


def scan(
    atlas: Path,
    output: Path,
    bbox: tuple[float, float, float, float],
    coordinate_encoding: str,
    match_limit: int,
    block_limit: int,
    start_offset: int,
    save_decoded: bool,
) -> dict[str, object]:
    min_lon, min_lat, max_lon, max_lat = bbox
    if coordinate_encoding == "degree-e7":
        scale_value = lambda value: round(value * 10_000_000)
        unscale_value = lambda value: value / 10_000_000
        scaled = tuple(scale_value(value) for value in bbox)
    elif coordinate_encoding == "degree-e7-lon-plus-90":
        scaled = (
            round((min_lon + 90.0) * 10_000_000),
            round(min_lat * 10_000_000),
            round((max_lon + 90.0) * 10_000_000),
            round(max_lat * 10_000_000),
        )
        unscale_value = lambda value: value / 10_000_000
    elif coordinate_encoding == "radian-e9":
        scale_value = lambda value: round(math.radians(value) * 1_000_000_000)
        unscale_value = lambda value: math.degrees(value / 1_000_000_000)
        scaled = tuple(scale_value(value) for value in bbox)
    else:
        raise ValueError(f"unknown coordinate encoding {coordinate_encoding}")
    min_lon_i, min_lat_i, max_lon_i, max_lat_i = scaled
    output.mkdir(parents=True, exist_ok=True)
    matches_path = output / "matches.jsonl"
    report_path = output / "report.json"
    checksum_path = output / "CHECKSUMS.sha256"
    file_size = atlas.stat().st_size
    block_offset = start_offset
    blocks = 0
    decoded_chunks = 0
    graph_chunks = 0
    failures = 0
    global_min_lon: int | None = None
    global_max_lon: int | None = None
    global_min_lat: int | None = None
    global_max_lat: int | None = None
    graph_bounds_samples: list[dict[str, object]] = []
    matches: list[dict[str, object]] = []
    progress(
        "start",
        atlas=atlas,
        bbox=f"{min_lon},{min_lat},{max_lon},{max_lat}",
        encoding=coordinate_encoding,
        match_limit=match_limit,
        start_offset=f"0x{start_offset:x}",
    )
    with atlas.open("rb") as source:
        while block_offset < file_size and (
            block_limit == 0 or blocks < block_limit
        ):
            source.seek(block_offset)
            header = source.read(0x20)
            if len(header) != 0x20:
                break
            block_name = _read_name(header)
            block_size = struct.unpack_from("<I", header, 0x10)[0]
            if (
                block_name is None
                or block_size < 0x20
                or block_offset + block_size > file_size
            ):
                raise ValueError(f"invalid Orion block at 0x{block_offset:x}")
            source.seek(block_offset)
            block = source.read(block_size)
            chunk_info = _parse_chunks(block)
            if chunk_info is not None:
                kind, pairs, cursor = chunk_info
                for chunk_index, (compressed_size, uncompressed_size) in enumerate(pairs):
                    compressed = block[cursor : cursor + compressed_size]
                    cursor += compressed_size
                    if compressed_size == 0:
                        continue
                    try:
                        decoded = _decompress(kind, compressed, uncompressed_size)
                    except (EOFError, lzma.LZMAError, ValueError, zlib.error):
                        failures += 1
                        continue
                    decoded_chunks += 1
                    schema = parse_logical_schema(decoded)
                    if schema is None:
                        continue
                    names = schema_names(schema)
                    if not {"PointLlh", "EdgeRoadElement", "NodeRoadElement"} <= names:
                        continue
                    graph_chunks += 1
                    table = parse_exact_column_table(decoded, schema)
                    if table is None:
                        raise ValueError(
                            f"graph chunk at 0x{block_offset:x} has no exact table"
                        )
                    columns = point_columns(decoded, schema, table)
                    if columns is None:
                        continue
                    longitudes, latitudes = columns
                    if not longitudes:
                        continue
                    chunk_min_lon = min(longitudes)
                    chunk_max_lon = max(longitudes)
                    chunk_min_lat = min(latitudes)
                    chunk_max_lat = max(latitudes)
                    global_min_lon = (
                        chunk_min_lon
                        if global_min_lon is None
                        else min(global_min_lon, chunk_min_lon)
                    )
                    global_max_lon = (
                        chunk_max_lon
                        if global_max_lon is None
                        else max(global_max_lon, chunk_max_lon)
                    )
                    global_min_lat = (
                        chunk_min_lat
                        if global_min_lat is None
                        else min(global_min_lat, chunk_min_lat)
                    )
                    global_max_lat = (
                        chunk_max_lat
                        if global_max_lat is None
                        else max(global_max_lat, chunk_max_lat)
                    )
                    if len(graph_bounds_samples) < 8:
                        graph_bounds_samples.append(
                            {
                                "block_offset_hex": f"0x{block_offset:x}",
                                "raw_bounds": [
                                    chunk_min_lon,
                                    chunk_min_lat,
                                    chunk_max_lon,
                                    chunk_max_lat,
                                ],
                            }
                        )
                    inside = [
                        index
                        for index, (lon, lat) in enumerate(zip(longitudes, latitudes))
                        if min_lon_i <= lon <= max_lon_i
                        and min_lat_i <= lat <= max_lat_i
                    ]
                    if not inside:
                        continue
                    row = {
                        "block_offset": block_offset,
                        "block_offset_hex": f"0x{block_offset:x}",
                        "block_name": block_name,
                        "chunk_index": chunk_index,
                        "decoded_size": len(decoded),
                        "point_count": len(longitudes),
                        "points_inside_bbox": len(inside),
                        "longitude_min": chunk_min_lon,
                        "longitude_max": chunk_max_lon,
                        "latitude_min": chunk_min_lat,
                        "latitude_max": chunk_max_lat,
                        "first_inside_rows": [
                            {
                                "row": index,
                                "longitude": (
                                    longitudes[index] / 10_000_000 - 90.0
                                    if coordinate_encoding
                                    == "degree-e7-lon-plus-90"
                                    else unscale_value(longitudes[index])
                                ),
                                "latitude": unscale_value(latitudes[index]),
                            }
                            for index in inside[:16]
                        ],
                    }
                    if save_decoded:
                        ordinal = len(matches)
                        decoded_name = f"match_{ordinal:02d}.decoded.bin"
                        schema_name = f"match_{ordinal:02d}.schema.json"
                        (output / decoded_name).write_bytes(decoded)
                        (output / schema_name).write_text(
                            json.dumps(
                                {
                                    "block_offset": block_offset,
                                    "block_offset_hex": f"0x{block_offset:x}",
                                    "chunk_index": chunk_index,
                                    "schema": schema,
                                    "table": table,
                                    "groups": group_serialized_parts(
                                        schema, table["descriptors"]
                                    ),
                                },
                                indent=2,
                                sort_keys=True,
                            )
                            + "\n",
                            encoding="utf-8",
                        )
                        row["decoded_artifact"] = decoded_name
                        row["schema_artifact"] = schema_name
                    matches.append(row)
                    progress(
                        "match",
                        count=len(matches),
                        block=f"0x{block_offset:x}",
                        points=len(longitudes),
                        inside=len(inside),
                    )
                    if match_limit and len(matches) >= match_limit:
                        break
            blocks += 1
            block_offset += block_size
            if blocks % 1000 == 0:
                progress(
                    "scan",
                    blocks=blocks,
                    graph_chunks=graph_chunks,
                    matches=len(matches),
                )
            if match_limit and len(matches) >= match_limit:
                break
    matches_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in matches),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "matches_found" if matches else "no_matches",
        "source": {
            "path": str(atlas),
            "size": file_size,
            "read_only": True,
        },
        "bbox_degrees": {
            "min_longitude": min_lon,
            "min_latitude": min_lat,
            "max_longitude": max_lon,
            "max_latitude": max_lat,
        },
        "bbox_scaled": list(scaled),
        "coordinate_encoding": coordinate_encoding,
        "blocks_scanned": blocks,
        "start_offset": start_offset,
        "start_offset_hex": f"0x{start_offset:x}",
        "next_block_offset": block_offset,
        "next_block_offset_hex": f"0x{block_offset:x}",
        "decoded_chunks": decoded_chunks,
        "graph_chunks": graph_chunks,
        "decode_failures": failures,
        "matching_chunks": len(matches),
        "global_raw_point_bounds": [
            global_min_lon,
            global_min_lat,
            global_max_lon,
            global_max_lat,
        ],
        "graph_bounds_samples": graph_bounds_samples,
        "stopped_at_match_limit": bool(match_limit and len(matches) >= match_limit),
        "artifacts": {
            "matches": matches_path.name,
            "saved_decoded_chunks": save_decoded,
        },
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    artifact_paths = [matches_path, report_path]
    if save_decoded:
        artifact_paths.extend(sorted(output.glob("match_*.decoded.bin")))
        artifact_paths.extend(sorted(output.glob("match_*.schema.json")))
    checksum_path.write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in artifact_paths),
        encoding="ascii",
    )
    progress("complete", blocks=blocks, matches=len(matches), output=output)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--bbox",
        nargs=4,
        type=float,
        metavar=("MIN_LON", "MIN_LAT", "MAX_LON", "MAX_LAT"),
        default=(18.4, 41.8, 23.2, 46.3),
    )
    parser.add_argument("--match-limit", type=int, default=8)
    parser.add_argument("--block-limit", type=int, default=0)
    parser.add_argument("--start-offset", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--save-decoded", action="store_true")
    parser.add_argument(
        "--coordinate-encoding",
        choices=("degree-e7", "degree-e7-lon-plus-90", "radian-e9"),
        default="degree-e7",
    )
    args = parser.parse_args()
    if args.match_limit < 0 or args.block_limit < 0 or args.start_offset < 0:
        parser.error("limits must not be negative")
    min_lon, min_lat, max_lon, max_lat = args.bbox
    if min_lon > max_lon or min_lat > max_lat:
        parser.error("invalid bbox ordering")
    try:
        report = scan(
            args.atlas,
            args.output,
            tuple(args.bbox),
            args.coordinate_encoding,
            args.match_limit,
            args.block_limit,
            args.start_offset,
            args.save_decoded,
        )
    except (OSError, ValueError) as error:
        print(f"orion-spatial-probe error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
