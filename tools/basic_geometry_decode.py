#!/usr/bin/env python3
"""Decode firmware-confirmed MIB Basic edge geometry into normalized polylines.

The decoder implements the coordinate visitor at Ghidra VA 0x01559a60:

* geometry header bytes 0..15 are the signed cluster bounding box;
* byte 20 bit 0 selects u16 or u32 coordinate components;
* byte 21 is the coordinate scale;
* byte 22 is the coordinate-table entry count;
* the u16 at byte 16 points to entries containing a marker byte plus x/y;
* subrecord byte 2 counts signed int8 x/y delta pairs;
* subrecord byte 0 bits 0/1 select node-table or explicit start/end points.

Every input edge is decoded and validated.  A bounded JSONL sample is emitted by
default; ``--sample-limit 0`` streams every normalized edge to the JSONL output.
"""

from __future__ import annotations

import argparse
import collections
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys
from basic_geometry_grammar import Grammar, split_subrecords
from basic_semantic_probe import geometry_record_offsets
from psf_decode import (
    PsfError,
    _decode_indexed_lzma,
    _mercator_to_wgs84,
    read_basic_triple_handle_index,
)


SCHEMA_VERSION = 1
EDGE_DESCRIPTOR_STRIDE = 9
GEOMETRY_OFFSET_TABLE_BASE = 24
GEOMETRY_GRAMMAR = Grammar(
    record_header_base=2,
    subrecord_base=3,
    subrecord_stride=2,
)


@dataclass(frozen=True)
class Point:
    x: int
    y: int

    def as_list(self) -> list[int]:
        return [self.x, self.y]


@dataclass(frozen=True)
class DecodedPart:
    index: int
    flags: int
    secondary_flags: int
    delta_pair_count: int
    start_source: str
    end_source: str
    start_table_index: int | None
    end_table_index: int | None
    points: tuple[Point, ...]
    extension: bytes
    offset: int
    size: int


@dataclass(frozen=True)
class GeometryCluster:
    cluster_id: int
    topology: bytes
    geometry: bytes
    bbox: tuple[int, int, int, int]
    header_flags: int
    scale: int
    coordinate_count: int
    coordinate_table_offset: int
    component_width: int
    coordinate_entry_stride: int
    edge_descriptor_base: int
    edge_count: int
    node_count: int
    geometry_offsets: tuple[int, ...]
    geometry_offset_table_end: int

    @property
    def coordinate_pair_width(self) -> int:
        return self.component_width * 2

    @property
    def coordinate_mode(self) -> str:
        return f"u{self.component_width * 8}-components"


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"geometry-decode stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_pair(data: bytes, offset: int, component_width: int) -> tuple[int, int]:
    if component_width == 2:
        try:
            return struct.unpack_from("<HH", data, offset)
        except struct.error as error:
            raise PsfError("truncated u16 geometry coordinate pair") from error
    if component_width == 4:
        try:
            return struct.unpack_from("<II", data, offset)
        except struct.error as error:
            raise PsfError("truncated u32 geometry coordinate pair") from error
    raise PsfError(f"unsupported geometry component width {component_width}")


def _absolute_point(cluster: GeometryCluster, encoded: tuple[int, int]) -> Point:
    return Point(
        cluster.bbox[0] + cluster.scale * encoded[0],
        cluster.bbox[1] + cluster.scale * encoded[1],
    )


def coordinate_table_entry(
    cluster: GeometryCluster, index: int
) -> tuple[Point, int, tuple[int, int]]:
    if not 0 <= index < cluster.coordinate_count:
        raise PsfError(
            f"cluster {cluster.cluster_id} coordinate table index {index} "
            f"outside count {cluster.coordinate_count}"
        )
    start = cluster.coordinate_table_offset + index * cluster.coordinate_entry_stride
    end = start + cluster.coordinate_entry_stride
    if end > len(cluster.geometry):
        raise PsfError(f"cluster {cluster.cluster_id} truncated coordinate table")
    marker = cluster.geometry[start]
    encoded = _read_pair(cluster.geometry, start + 1, cluster.component_width)
    return _absolute_point(cluster, encoded), marker, encoded


def _explicit_point(
    cluster: GeometryCluster, record: bytes, offset: int
) -> tuple[Point, tuple[int, int]]:
    encoded = _read_pair(record, offset, cluster.component_width)
    return _absolute_point(cluster, encoded), encoded


def decode_geometry_record(
    cluster: GeometryCluster,
    edge_index: int,
) -> tuple[DecodedPart, ...]:
    if not 0 <= edge_index < cluster.edge_count:
        raise PsfError(
            f"edge {edge_index} outside cluster {cluster.cluster_id} count {cluster.edge_count}"
        )
    descriptor_at = cluster.edge_descriptor_base + edge_index * EDGE_DESCRIPTOR_STRIDE
    descriptor = cluster.topology[
        descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
    ]
    if len(descriptor) != EDGE_DESCRIPTOR_STRIDE:
        raise PsfError(f"cluster {cluster.cluster_id} truncated edge descriptor")

    record_start = cluster.geometry_offsets[edge_index]
    record_end = (
        cluster.geometry_offsets[edge_index + 1]
        if edge_index + 1 < cluster.edge_count
        else len(cluster.geometry)
    )
    record = cluster.geometry[record_start:record_end]
    boundaries = split_subrecords(record, cluster.header_flags, GEOMETRY_GRAMMAR)
    if boundaries is None:
        raise PsfError(
            f"cluster {cluster.cluster_id} edge {edge_index} has invalid subrecord boundaries"
        )

    parts: list[DecodedPart] = []
    for part_index, (start, end) in enumerate(boundaries):
        if start + 3 > end:
            raise PsfError(
                f"cluster {cluster.cluster_id} edge {edge_index} truncated subrecord"
            )
        flags = record[start]
        secondary_flags = record[start + 1]
        delta_pair_count = record[start + 2]
        delta_start = start + GEOMETRY_GRAMMAR.subrecord_base
        delta_end = delta_start + delta_pair_count * GEOMETRY_GRAMMAR.subrecord_stride
        if delta_end > end:
            raise PsfError(
                f"cluster {cluster.cluster_id} edge {edge_index} truncated delta pairs"
            )
        cursor = delta_end

        start_table_index: int | None = None
        if flags & 0x01:
            start_table_index = descriptor[5]
            first, _, _ = coordinate_table_entry(cluster, start_table_index)
            start_source = "coordinate-table"
        else:
            first, _ = _explicit_point(cluster, record, cursor)
            cursor += cluster.coordinate_pair_width
            start_source = "explicit"

        points = [first]
        current = first
        for delta_index in range(delta_pair_count):
            x_byte = record[delta_start + delta_index * 2]
            y_byte = record[delta_start + delta_index * 2 + 1]
            dx = x_byte if x_byte < 0x80 else x_byte - 0x100
            dy = y_byte if y_byte < 0x80 else y_byte - 0x100
            current = Point(
                current.x + cluster.scale * dx,
                current.y + cluster.scale * dy,
            )
            points.append(current)

        end_table_index: int | None = None
        if flags & 0x02:
            end_table_index = descriptor[6]
            last, _, _ = coordinate_table_entry(cluster, end_table_index)
            end_source = "coordinate-table"
        else:
            last, _ = _explicit_point(cluster, record, cursor)
            cursor += cluster.coordinate_pair_width
            end_source = "explicit"
        if cursor > end:
            raise PsfError(
                f"cluster {cluster.cluster_id} edge {edge_index} coordinate core overruns subrecord"
            )
        points.append(last)
        parts.append(
            DecodedPart(
                index=part_index,
                flags=flags,
                secondary_flags=secondary_flags,
                delta_pair_count=delta_pair_count,
                start_source=start_source,
                end_source=end_source,
                start_table_index=start_table_index,
                end_table_index=end_table_index,
                points=tuple(points),
                extension=record[cursor:end],
                offset=start,
                size=end - start,
            )
        )
    return tuple(parts)


def _build_cluster(cluster_id: int, topology: bytes, geometry: bytes) -> GeometryCluster:
    if len(topology) < 7 or len(geometry) < 24:
        raise PsfError(f"cluster {cluster_id} has a truncated Basic handle")
    edge_count = topology[2]
    node_count = topology[4]
    if edge_count != geometry[23]:
        raise PsfError(
            f"cluster {cluster_id} topology/geometry edge counts differ: "
            f"{edge_count} != {geometry[23]}"
        )
    if node_count != geometry[22]:
        raise PsfError(
            f"cluster {cluster_id} topology/coordinate-table node counts differ: "
            f"{node_count} != {geometry[22]}"
        )
    edge_descriptor_base = struct.unpack_from("<H", topology)[0] & 0x7FFF
    if edge_descriptor_base + edge_count * EDGE_DESCRIPTOR_STRIDE > len(topology):
        raise PsfError(f"cluster {cluster_id} edge descriptor table overruns topology")
    offsets, offset_table_end = geometry_record_offsets(
        geometry, GEOMETRY_OFFSET_TABLE_BASE
    )
    if len(offsets) != edge_count or offsets != sorted(set(offsets)):
        raise PsfError(f"cluster {cluster_id} invalid geometry record offsets")
    header_flags = geometry[20]
    component_width = 4 if header_flags & 0x01 else 2
    coordinate_count = geometry[22]
    coordinate_table_offset = struct.unpack_from("<H", geometry, 16)[0]
    coordinate_entry_stride = 1 + component_width * 2
    coordinate_table_end = (
        coordinate_table_offset + coordinate_count * coordinate_entry_stride
    )
    if coordinate_count and coordinate_table_offset < offset_table_end:
        raise PsfError(
            f"cluster {cluster_id} coordinate table overlaps geometry offset table"
        )
    if coordinate_table_end > offsets[0]:
        raise PsfError(
            f"cluster {cluster_id} coordinate table overlaps first geometry record"
        )
    bbox = struct.unpack_from("<4i", geometry)
    if bbox[0] > bbox[2] or bbox[1] > bbox[3]:
        raise PsfError(f"cluster {cluster_id} has inverted geometry bbox")
    return GeometryCluster(
        cluster_id=cluster_id,
        topology=topology,
        geometry=geometry,
        bbox=bbox,
        header_flags=header_flags,
        scale=geometry[21],
        coordinate_count=coordinate_count,
        coordinate_table_offset=coordinate_table_offset,
        component_width=component_width,
        coordinate_entry_stride=coordinate_entry_stride,
        edge_descriptor_base=edge_descriptor_base,
        edge_count=edge_count,
        node_count=node_count,
        geometry_offsets=tuple(offsets),
        geometry_offset_table_end=offset_table_end,
    )


def _inside_bbox(point: Point, bbox: tuple[int, int, int, int]) -> bool:
    return bbox[0] <= point.x <= bbox[2] and bbox[1] <= point.y <= bbox[3]


def _sample_item(
    cluster: GeometryCluster,
    edge_index: int,
    parts: tuple[DecodedPart, ...],
) -> dict[str, object]:
    edge_id = (cluster.cluster_id << 8) | edge_index
    descriptor_at = cluster.edge_descriptor_base + edge_index * EDGE_DESCRIPTOR_STRIDE
    descriptor = cluster.topology[
        descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE
    ]
    record_start = cluster.geometry_offsets[edge_index]
    record_end = (
        cluster.geometry_offsets[edge_index + 1]
        if edge_index + 1 < cluster.edge_count
        else len(cluster.geometry)
    )
    record = cluster.geometry[record_start:record_end]
    first_part = parts[0].offset if parts else len(record)
    normalized_parts = []
    for part in parts:
        wgs84 = [_mercator_to_wgs84(point.x, point.y) for point in part.points]
        normalized_parts.append(
            {
                "index": part.index,
                "flags": part.flags,
                "secondary_flags": part.secondary_flags,
                "delta_pair_count": part.delta_pair_count,
                "start_source": part.start_source,
                "end_source": part.end_source,
                "start_coordinate_table_index": part.start_table_index,
                "end_coordinate_table_index": part.end_table_index,
                "points_mercator": [point.as_list() for point in part.points],
                "points_wgs84": [[longitude, latitude] for longitude, latitude in wgs84],
                "extension_size": len(part.extension),
                "extension_hex": part.extension.hex(),
                "subrecord_offset": part.offset,
                "subrecord_size": part.size,
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "basic-edge-normalized-geometry",
        "cluster_id": cluster.cluster_id,
        "edge_index": edge_index,
        "edge_id": edge_id,
        "edge_id_hex": f"0x{edge_id:08x}",
        "cluster_bbox_mercator": list(cluster.bbox),
        "coordinate_mode": cluster.coordinate_mode,
        "coordinate_scale": cluster.scale,
        "coordinate_table_count": cluster.coordinate_count,
        "descriptor_hex": descriptor.hex(),
        "descriptor_endpoint_a_external": bool(descriptor[4] & 0x40),
        "descriptor_endpoint_b_external": bool(descriptor[4] & 0x80),
        "geometry_record_decoded_offset": record_start,
        "geometry_record_size": len(record),
        "geometry_record_header_hex": record[:first_part].hex(),
        "parts": normalized_parts,
    }


def _group_entries(index: dict[str, object]) -> tuple[list[int], dict[int, dict[int, dict[str, object]]]]:
    grouped: dict[int, dict[int, dict[str, object]]] = {}
    order: list[int] = []
    for raw_entry in index["entries"]:  # type: ignore[index]
        entry = raw_entry  # type: ignore[assignment]
        cluster_id = int(entry["cluster_id"])
        handle = int(entry["handle_index"])
        if cluster_id not in grouped:
            grouped[cluster_id] = {}
            order.append(cluster_id)
        if handle in grouped[cluster_id]:
            raise PsfError(f"duplicate handle {handle} for Basic cluster {cluster_id}")
        grouped[cluster_id][handle] = entry
    if any(set(handles) != {0, 1, 2} for handles in grouped.values()):
        raise PsfError("Basic triple index does not contain exactly three handles per cluster")
    return order, grouped


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    cluster_order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "edge_geometry_sample.jsonl"
    sample_temporary = sample_path.with_suffix(sample_path.suffix + ".tmp")

    counts = collections.Counter()
    header_flag_counts = collections.Counter()
    scale_counts = collections.Counter()
    coordinate_mode_counts = collections.Counter()
    endpoint_source_counts = collections.Counter()
    delta_pair_counts = collections.Counter()
    extension_counts = collections.Counter()
    failures: list[dict[str, object]] = []
    failure_count = 0
    point_outside_bbox_count = 0
    point_outside_bbox_examples: list[dict[str, object]] = []
    table_point_outside_bbox_count = 0
    table_point_outside_bbox_examples: list[dict[str, object]] = []
    maximum_parts_per_edge = 0
    maximum_points_per_part = 0
    sample_count = 0
    overall_extent: list[int] | None = None

    _progress("decode", clusters_total=len(cluster_order))
    with psf.open("rb") as source, sample_temporary.open(
        "w", encoding="utf-8"
    ) as sample_destination:
        for cluster_ordinal, cluster_id in enumerate(cluster_order, 1):
            handles = grouped[cluster_id]
            topology = _decode_indexed_lzma(source, handles[0])
            geometry = _decode_indexed_lzma(source, handles[1])
            cluster = _build_cluster(cluster_id, topology, geometry)
            counts["clusters"] += 1
            counts["coordinate_table_entries"] += cluster.coordinate_count
            counts["topology_nodes"] += cluster.node_count
            header_flag_counts[cluster.header_flags] += 1
            scale_counts[cluster.scale] += 1
            coordinate_mode_counts[cluster.coordinate_mode] += 1

            for coordinate_index in range(cluster.coordinate_count):
                point, _, _ = coordinate_table_entry(cluster, coordinate_index)
                if not _inside_bbox(point, cluster.bbox):
                    table_point_outside_bbox_count += 1
                    if len(table_point_outside_bbox_examples) < 100:
                        table_point_outside_bbox_examples.append(
                            {
                                "cluster_id": cluster_id,
                                "coordinate_index": coordinate_index,
                                "point": point.as_list(),
                                "bbox": list(cluster.bbox),
                            }
                        )

            counts["edges_expected"] += cluster.edge_count
            for edge_index in range(cluster.edge_count):
                try:
                    parts = decode_geometry_record(cluster, edge_index)
                except PsfError as error:
                    failure_count += 1
                    if len(failures) < 100:
                        failures.append(
                            {
                                "cluster_id": cluster_id,
                                "edge_index": edge_index,
                                "error": str(error),
                            }
                        )
                    continue
                counts["edges_decoded"] += 1
                counts["subrecords"] += len(parts)
                maximum_parts_per_edge = max(maximum_parts_per_edge, len(parts))
                for part in parts:
                    counts["points"] += len(part.points)
                    counts["delta_pairs"] += part.delta_pair_count
                    maximum_points_per_part = max(
                        maximum_points_per_part, len(part.points)
                    )
                    endpoint_source_counts[f"start:{part.start_source}"] += 1
                    endpoint_source_counts[f"end:{part.end_source}"] += 1
                    delta_pair_counts[part.delta_pair_count] += 1
                    extension_counts["present" if part.extension else "absent"] += 1
                    for point_index, point in enumerate(part.points):
                        if overall_extent is None:
                            overall_extent = [point.x, point.y, point.x, point.y]
                        else:
                            overall_extent[0] = min(overall_extent[0], point.x)
                            overall_extent[1] = min(overall_extent[1], point.y)
                            overall_extent[2] = max(overall_extent[2], point.x)
                            overall_extent[3] = max(overall_extent[3], point.y)
                        if not _inside_bbox(point, cluster.bbox):
                            point_outside_bbox_count += 1
                            if len(point_outside_bbox_examples) < 100:
                                point_outside_bbox_examples.append(
                                    {
                                        "cluster_id": cluster_id,
                                        "edge_index": edge_index,
                                        "part_index": part.index,
                                        "point_index": point_index,
                                        "point": point.as_list(),
                                        "bbox": list(cluster.bbox),
                                    }
                                )
                if sample_limit == 0 or sample_count < sample_limit:
                    sample_destination.write(
                        json.dumps(
                            _sample_item(cluster, edge_index, parts),
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    sample_count += 1

            if cluster_ordinal % 250 == 0 or cluster_ordinal == len(cluster_order):
                _progress(
                    "decode-progress",
                    clusters=cluster_ordinal,
                    total=len(cluster_order),
                    edges=counts["edges_decoded"],
                    failures=failure_count,
                    outside=point_outside_bbox_count,
                )
    sample_temporary.replace(sample_path)

    validation_ok = (
        failure_count == 0
        and counts["edges_decoded"] == counts["edges_expected"]
        and point_outside_bbox_count == 0
        and table_point_outside_bbox_count == 0
    )
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated" if validation_ok else "validation-failed",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "scope": {
            "index_kind": "basic-id-triple",
            "handles_decoded": [0, 1],
            "semantic_output": "ordered x/y points for every geometry subrecord",
            "remaining_raw": "optional per-subrecord extension payloads",
            "travel_direction_note": "point order follows firmware endpoint slots A then B; routing direction is separate",
        },
        "layout": {
            "edge_descriptor_stride": EDGE_DESCRIPTOR_STRIDE,
            "geometry_record_offset_table_base": GEOMETRY_OFFSET_TABLE_BASE,
            "geometry_record_header_base": GEOMETRY_GRAMMAR.record_header_base,
            "geometry_subrecord_base": GEOMETRY_GRAMMAR.subrecord_base,
            "geometry_delta_pair_stride": GEOMETRY_GRAMMAR.subrecord_stride,
            "cluster_bbox": "four little-endian signed i32 values: min_x,min_y,max_x,max_y",
            "coordinate_table_offset": "little-endian u16 at cluster byte 16",
            "coordinate_mode": "cluster byte 20 bit 0: clear=u16 x/y, set=u32 x/y",
            "coordinate_scale": "cluster byte 21",
            "coordinate_table_count": "cluster byte 22",
            "coordinate_table_entry": "one marker byte followed by little-endian x/y components",
            "absolute_coordinate_formula": "cluster_min + scale * encoded_component",
            "delta_formula": "previous_point + scale * signed_int8_pair",
            "endpoint_flags": "subrecord byte 0 bits 0/1: set=descriptor coordinate-table index, clear=explicit pair",
        },
        "counts": {
            **dict(counts),
            "cluster_header_flag_values": {
                str(key): value for key, value in sorted(header_flag_counts.items())
            },
            "cluster_scale_values": {
                str(key): value for key, value in sorted(scale_counts.items())
            },
            "coordinate_modes": dict(sorted(coordinate_mode_counts.items())),
            "endpoint_sources": dict(sorted(endpoint_source_counts.items())),
            "delta_pair_count_values": {
                str(key): value for key, value in sorted(delta_pair_counts.items())
            },
            "extensions": dict(sorted(extension_counts.items())),
            "maximum_parts_per_edge": maximum_parts_per_edge,
            "maximum_points_per_part": maximum_points_per_part,
        },
        "validation": {
            "all_edges_decoded": counts["edges_decoded"] == counts["edges_expected"],
            "decode_failure_count": failure_count,
            "decode_failure_examples": failures,
            "all_coordinate_table_points_inside_cluster_bbox": table_point_outside_bbox_count == 0,
            "coordinate_table_point_outside_bbox_count": table_point_outside_bbox_count,
            "coordinate_table_point_outside_bbox_examples": table_point_outside_bbox_examples,
            "all_decoded_points_inside_cluster_bbox": point_outside_bbox_count == 0,
            "decoded_point_outside_bbox_count": point_outside_bbox_count,
            "decoded_point_outside_bbox_examples": point_outside_bbox_examples,
            "overall_decoded_extent_mercator": overall_extent,
        },
        "evidence": {
            "firmware_library": "navigation/libPathfinderApp.so",
            "ghidra_image_base_slide": "+0x10000",
            "geometry_record_visitor": "0x0154fd30",
            "bbox_visitor_constructor": "0x01559a0c",
            "coordinate_decoder": "0x01559a60",
            "coordinate_decoder_vtable": "0x017172f0",
        },
        "artifacts": {
            "report": "report.json",
            "edge_geometry_sample": sample_path.name,
            "edge_geometry_sample_count": sample_count,
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    checksums = output / "CHECKSUMS.sha256"
    checksums.write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(sample_path)}  {sample_path.name}\n",
        encoding="ascii",
    )
    _progress("complete", status=report["status"], output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=100,
        help="normalized edges to emit; 0 emits every edge",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_geometry_decode: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "clusters": report["counts"]["clusters"],  # type: ignore[index]
                "edges": report["counts"]["edges_decoded"],  # type: ignore[index]
                "subrecords": report["counts"]["subrecords"],  # type: ignore[index]
                "points": report["counts"]["points"],  # type: ignore[index]
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
