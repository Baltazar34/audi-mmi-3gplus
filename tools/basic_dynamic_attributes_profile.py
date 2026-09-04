#!/usr/bin/env python3
"""Profile Basic dynamic edge-attribute directories over the full PSF corpus."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys

from basic_dynamic_attributes import (
    decode_dynamic_attribute_directory,
    decode_fixed_width_edge_records,
    decode_type3_edge_records,
    decode_type5_edge_records,
    decode_time_condition,
)
from basic_geometry_decode import EDGE_DESCRIPTOR_STRIDE, _build_cluster, _group_entries
from basic_road_attributes import decode_automotive_attributes
from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 1
FIXED_WIDTH_TYPES = {
    5: (4, True),   # firmware VA 0x014a69e8: byte-0 edge key, four-byte stride
    9: (4, False),  # full-corpus framing only; record semantics intentionally raw
}


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"basic-dynamic-attributes-profile stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _counter(counter: collections.Counter[object]) -> dict[str, int]:
    return {
        str(key): value
        for key, value in sorted(counter.items(), key=lambda item: str(item[0]))
    }


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "dynamic_directory_samples.jsonl"
    sample_temporary = sample_path.with_suffix(".jsonl.tmp")

    counts = collections.Counter()
    directory_type_sequences = collections.Counter()
    type_payload_sizes: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    type_payload_counts: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    type_record_widths: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    type_edge_key_counts: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    type3_selector_flags = collections.Counter()
    type3_condition_first_bytes = collections.Counter()
    type3_condition_shapes = collections.Counter()
    type3_time_ranges = collections.Counter()
    type3_direction_modes = collections.Counter()
    type3_timezone_indices = collections.Counter()
    dynamic_edges_by_directory_types = collections.Counter()
    invalid: list[dict[str, object]] = []
    samples_written = 0

    _progress("decode", clusters_total=len(order))
    with psf.open("rb") as source, sample_temporary.open("w", encoding="utf-8") as samples:
        for ordinal, cluster_id in enumerate(order, 1):
            try:
                topology = _decode_indexed_lzma(source, grouped[cluster_id][0])
                geometry = _decode_indexed_lzma(source, grouped[cluster_id][1])
                cluster = _build_cluster(cluster_id, topology, geometry)
                directory = decode_dynamic_attribute_directory(topology)
                dynamic_edge_indexes: list[int] = []
                for edge_index in range(cluster.edge_count):
                    start = cluster.edge_descriptor_base + edge_index * EDGE_DESCRIPTOR_STRIDE
                    automotive = decode_automotive_attributes(
                        topology[start : start + EDGE_DESCRIPTOR_STRIDE]
                    )
                    if automotive.has_dynamic_extension:
                        dynamic_edge_indexes.append(edge_index)
                counts["clusters"] += 1
                counts["edges"] += cluster.edge_count
                counts["dynamic_marker_edges"] += len(dynamic_edge_indexes)
                if directory is None:
                    counts["clusters_without_directory"] += 1
                    if dynamic_edge_indexes:
                        raise PsfError("dynamic-marker edge exists without a dynamic directory")
                    continue

                counts["clusters_with_directory"] += 1
                counts["directory_entries"] += len(directory.entries)
                types = tuple(entry.type_id for entry in directory.entries)
                directory_type_sequences[types] += 1
                if dynamic_edge_indexes:
                    counts["clusters_with_dynamic_marker_edges"] += 1
                    dynamic_edges_by_directory_types[types] += len(dynamic_edge_indexes)

                entry_samples: list[dict[str, object]] = []
                for entry in directory.entries:
                    counts[f"type_{entry.type_id}_entries"] += 1
                    type_payload_sizes[entry.type_id][len(entry.payload)] += 1
                    if entry.payload:
                        declared_count = entry.payload[0]
                        type_payload_counts[entry.type_id][declared_count] += 1
                        if declared_count and (len(entry.payload) - 1) % declared_count == 0:
                            inferred_width = (len(entry.payload) - 1) // declared_count
                            type_record_widths[entry.type_id][inferred_width] += 1
                    fixed_width_info = FIXED_WIDTH_TYPES.get(entry.type_id)
                    edge_keys: list[int] | None = None
                    record_first_bytes: list[int] | None = None
                    if fixed_width_info is not None:
                        fixed_width, first_byte_is_edge_key = fixed_width_info
                        records = decode_fixed_width_edge_records(entry, fixed_width)
                        record_first_bytes = [record[0] for record in records]
                        if first_byte_is_edge_key:
                            edge_keys = record_first_bytes
                            if len(edge_keys) != len(set(edge_keys)):
                                raise PsfError(
                                    f"type-{entry.type_id} fixed-width edge keys are not unique"
                                )
                            if any(edge_key >= cluster.edge_count for edge_key in edge_keys):
                                raise PsfError(
                                    f"type-{entry.type_id} edge key outside cluster edge count"
                                )
                        if edge_keys is not None:
                            type_edge_key_counts[entry.type_id][len(edge_keys)] += 1
                        counts[f"type_{entry.type_id}_records"] += len(records)
                        if entry.type_id == 5:
                            decoded_type5 = decode_type5_edge_records(entry)
                            counts["type_5_scale_by_16_records"] += sum(
                                record.scale_by_16 for record in decoded_type5
                            )
                    if entry.type_id == 3:
                        type3_records = decode_type3_edge_records(entry)
                        type3_edge_keys = [record.edge_index for record in type3_records]
                        if any(edge_key >= cluster.edge_count for edge_key in type3_edge_keys):
                            raise PsfError("type-3 edge key outside cluster edge count")
                        counts["type_3_records"] += len(type3_records)
                        counts["type_3_unique_condition_objects"] += len(
                            {record.condition_offset for record in type3_records}
                        )
                        for record in type3_records:
                            type3_selector_flags[record.selector_flags] += 1
                            type3_direction_modes[
                                (record.a_to_b, record.b_to_a)
                            ] += 1
                            type3_timezone_indices[
                                (record.selector_flags & 0x70) >> 4
                            ] += 1
                            type3_condition_first_bytes[record.condition[0]] += 1
                            decoded_condition = decode_time_condition(record.condition)
                            type3_condition_shapes[
                                (
                                    decoded_condition.year_range is not None,
                                    "mask" if decoded_condition.month_mask is not None else (
                                        "range" if decoded_condition.month_range is not None else "none"
                                    ),
                                    "mask" if decoded_condition.day_of_month_mask is not None else (
                                        "range" if decoded_condition.day_of_month_range is not None else "none"
                                    ),
                                    decoded_condition.weekday_mask is not None,
                                    decoded_condition.start_time_slot_15m is not None,
                                )
                            ] += 1
                            if decoded_condition.start_time_slot_15m is not None:
                                type3_time_ranges[
                                    (
                                        decoded_condition.start_time_slot_15m,
                                        decoded_condition.end_time_slot_15m,
                                    )
                                ] += 1
                    entry_samples.append(
                        {
                            "type_id": entry.type_id,
                            "relative_offset": entry.relative_offset,
                            "payload_size": len(entry.payload),
                            "declared_count": entry.payload[0] if entry.payload else None,
                            "edge_keys": edge_keys,
                            "record_first_bytes": record_first_bytes,
                            "payload_hex": entry.payload.hex(),
                        }
                    )

                if sample_limit == 0 or samples_written < sample_limit:
                    samples.write(
                        json.dumps(
                            {
                                "cluster_id": cluster_id,
                                "edge_count": cluster.edge_count,
                                "dynamic_marker_edge_indexes": dynamic_edge_indexes,
                                "directory_offset": directory.offset,
                                "directory_header_size": directory.header_size,
                                "entries": entry_samples,
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    samples_written += 1
            except (PsfError, ValueError) as error:
                counts["invalid_clusters"] += 1
                if len(invalid) < 100:
                    invalid.append({"cluster_id": cluster_id, "error": str(error)})

            if ordinal % 250 == 0 or ordinal == len(order):
                _progress(
                    "decode-progress",
                    clusters=ordinal,
                    total=len(order),
                    dynamic_edges=counts["dynamic_marker_edges"],
                    invalid=counts["invalid_clusters"],
                )
    sample_temporary.replace(sample_path)

    valid = counts["invalid_clusters"] == 0
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "dynamic-directory-validated" if valid else "validation-failed",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "firmware_evidence": {
            "directory_lookup_ghidra_va": "0x014a67e0",
            "time_dependent_direction_ghidra_va": "0x014a6a88",
            "type_3_unpacker_ghidra_va": "0x014a9858",
            "type_3_selector_ghidra_va": "0x014a94f0",
            "type_3_calendar_time_evaluator_ghidra_va": "0x014aa5f8",
            "vehicle_hov_access_ghidra_vas": ["0x014a6f44", "0x014a714c", "0x014a72b4"],
            "fixed_width_type_5_ghidra_va": "0x014a69e8",
            "type_5_caller_ghidra_va": "0x00977af8 (stores decoded value multiplied by 100)",
            "type_9_framing": "corpus-proven count plus four-byte records; fields remain raw",
            "directory_format": "u8 count; repeated (u8 type, u16le relative payload offset)",
            "topology_pointer": "u24le at bytes 12..14",
        },
        "counts": dict(counts),
        "directory_type_sequences": _counter(directory_type_sequences),
        "dynamic_marker_edges_by_directory_types": _counter(dynamic_edges_by_directory_types),
        "type_payload_size_distributions": {
            str(type_id): _counter(values) for type_id, values in sorted(type_payload_sizes.items())
        },
        "type_declared_count_distributions": {
            str(type_id): _counter(values) for type_id, values in sorted(type_payload_counts.items())
        },
        "type_whole_payload_record_width_candidates": {
            str(type_id): _counter(values) for type_id, values in sorted(type_record_widths.items())
        },
        "fixed_width_type_edge_key_count_distributions": {
            str(type_id): _counter(values) for type_id, values in sorted(type_edge_key_counts.items())
        },
        "type_3": {
            "active_schema_layout": (
                "u16 count, u8 auxiliary_count=0, u16 payload_end, "
                "count * (u8 edge, u8 selector, u16le condition_offset)"
            ),
            "selector_flag_distribution": _counter(type3_selector_flags),
            "direction_selector_distribution": _counter(type3_direction_modes),
            "timezone_table_index_distribution": _counter(type3_timezone_indices),
            "query_group_policy": {
                "group_0": "query bits 0/1/2 = skip/evaluate/immediate",
                "group_1": "query bits 3/4/5 = skip/evaluate/immediate",
                "group_2": "query bits 6/7/8 = skip/evaluate/immediate",
                "firmware_evidence": "Ghidra VA 0x014a94f0",
            },
            "condition_first_byte_distribution": _counter(type3_condition_first_bytes),
            "condition_shape_distribution": _counter(type3_condition_shapes),
            "time_slot_range_distribution": _counter(type3_time_ranges),
            "condition_semantics": (
                "year/month/day-of-month/weekday/time fields decoded from VA 0x014aa33c..0x014aa5f8"
            ),
        },
        "validation": {
            "all_directories_and_confirmed_fixed_width_tables_valid": valid,
            "invalid_examples": invalid,
            "semantic_boundary": (
                "directory framing, firmware-confirmed type-5 edge records, and corpus-confirmed "
                "type-9 four-byte records and type-3 edge selectors are decoded; "
                "calendar/time condition objects are field-decoded; final query-time policy and "
                "vehicle-class payload subfields remain pending"
            ),
        },
        "artifacts": {
            "samples": sample_path.name,
            "samples_written": samples_written,
            "sample_limit": sample_limit,
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
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
    parser.add_argument("--sample-limit", type=int, default=200)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_dynamic_attributes_profile: {error}", file=sys.stderr)
        return 1
    return 0 if report["status"] == "dynamic-directory-validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
