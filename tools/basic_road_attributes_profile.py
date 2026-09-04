#!/usr/bin/env python3
"""Profile Basic road-attribute bytes over the complete PSF corpus.

The profiler deliberately names only the direction bits already proven by a
firmware consumer.  Every other byte/tag is emitted as raw distribution data
until its own consumer and full-corpus invariants are established.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys

from basic_geometry_decode import (
    EDGE_DESCRIPTOR_STRIDE,
    _build_cluster,
    _group_entries,
    decode_geometry_record,
)
from basic_road_attributes import (
    GeometryAttributeType,
    decode_automotive_attributes,
    decode_extended_passing_restriction_header,
    decode_extended_speed_limit,
    decode_geometry_attribute_stream,
    decode_lanes,
    decode_number_of_lanes,
    decode_simple_passing_restriction,
    decode_simple_speed_limit,
    decode_tagged_attribute_header,
    decode_tagged_attributes,
    decode_travel_direction,
    decode_urban_road,
)
from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 5


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"basic-road-attributes-profile stage={stage}{' ' if suffix else ''}{suffix}",
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
    return {str(key): value for key, value in sorted(counter.items(), key=lambda item: str(item[0]))}


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "attribute_samples.jsonl"
    sample_temporary = sample_path.with_suffix(".jsonl.tmp")

    counts = collections.Counter()
    descriptor_bytes = [collections.Counter() for _ in range(EDGE_DESCRIPTOR_STRIDE)]
    direction_modes = collections.Counter()
    direction_by_byte1_low7 = collections.Counter()
    descriptor_byte3_high_bits = collections.Counter()
    automotive_base_masks = collections.Counter()
    automotive_active_bits = collections.Counter()
    automotive_dynamic_extension = collections.Counter()
    descriptor_byte1_low7 = collections.Counter()
    automotive_bits_by_descriptor_byte1_low7 = collections.Counter()
    automotive_bits_by_edge_min_speed = collections.Counter()
    secondary_flags = collections.Counter()
    secondary_flag_active_bits = collections.Counter()
    edge_secondary_flag_456_tuples = collections.Counter()
    first_tag_types = collections.Counter()
    first_tag_continuation = collections.Counter()
    all_tag_types = collections.Counter()
    tag_sequences = collections.Counter()
    tag_sizes: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    simple_speed_limit_values = collections.Counter()
    simple_speed_limit_by_direction = collections.Counter()
    simple_speed_limit_edge_min_candidates = collections.Counter()
    extended_speed_limit_values = collections.Counter()
    extended_speed_limit_subtypes = collections.Counter()
    extended_speed_limit_directions = collections.Counter()
    extended_speed_limit_sources = collections.Counter()
    extended_speed_limit_pair_counts = collections.Counter()
    number_of_lanes_pairs = collections.Counter()
    number_of_lanes_by_direction = collections.Counter()
    extended_passing_headers = collections.Counter()
    lanes_record_counts = collections.Counter()
    lanes_low_nibbles = collections.Counter()
    lane_byte_0_low_nibbles = collections.Counter()
    lane_byte_0_flags = collections.Counter()
    lane_byte_1_low_nibble_codes = collections.Counter()
    lane_byte_2_high_nibble_codes = collections.Counter()
    lane_byte_3_low_3_bits_codes = collections.Counter()
    lane_firmware_category_masks = collections.Counter()
    selected_payloads: dict[int, collections.Counter[str]] = {
        type_id: collections.Counter() for type_id in (2, 13, 14, 15, 16)
    }
    terminal_single_tag_lengths: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    continued_extension_lengths: dict[int, collections.Counter[int]] = collections.defaultdict(collections.Counter)
    tag_samples: dict[int, list[dict[str, object]]] = collections.defaultdict(list)
    extension_flag_mismatches: list[dict[str, object]] = []
    invalid_extensions: list[dict[str, object]] = []
    samples_written = 0

    _progress("decode", clusters_total=len(order))
    with psf.open("rb") as source, sample_temporary.open("w", encoding="utf-8") as samples:
        for ordinal, cluster_id in enumerate(order, 1):
            handles = grouped[cluster_id]
            topology = _decode_indexed_lzma(source, handles[0])
            geometry = _decode_indexed_lzma(source, handles[1])
            cluster = _build_cluster(cluster_id, topology, geometry)
            counts["clusters"] += 1
            for edge_index in range(cluster.edge_count):
                descriptor_at = cluster.edge_descriptor_base + edge_index * EDGE_DESCRIPTOR_STRIDE
                descriptor = topology[descriptor_at : descriptor_at + EDGE_DESCRIPTOR_STRIDE]
                direction = decode_travel_direction(descriptor)
                automotive = decode_automotive_attributes(descriptor)
                counts["edges"] += 1
                direction_modes[direction.mode] += 1
                direction_by_byte1_low7[(direction.mode, descriptor[1] & 0x7F)] += 1
                descriptor_byte3_high_bits[descriptor[3] & 0xFC] += 1
                automotive_base_masks[automotive.base_mask] += 1
                for bit_index in automotive.active_bit_indices:
                    automotive_active_bits[bit_index] += 1
                automotive_dynamic_extension[automotive.has_dynamic_extension] += 1
                descriptor_byte1_low7[descriptor[1] & 0x7F] += 1
                for byte_index, value in enumerate(descriptor):
                    descriptor_bytes[byte_index][value] += 1
                for bit_index in automotive.active_bit_indices:
                    automotive_bits_by_descriptor_byte1_low7[
                        (bit_index, descriptor[1] & 0x7F)
                    ] += 1

                parts = decode_geometry_record(cluster, edge_index)
                edge_simple_speed_limits: list[int] = []
                edge_has_number_of_lanes = False
                edge_has_simple_passing = False
                edge_has_extended_passing = False
                edge_has_lanes = False
                counts["parts"] += len(parts)
                for part in parts:
                    secondary_flags[part.secondary_flags] += 1
                    for bit_index in range(8):
                        if part.secondary_flags & (1 << bit_index):
                            secondary_flag_active_bits[bit_index] += 1
                    extension_present = bool(part.extension)
                    flagged_present = bool(part.secondary_flags & 0x80)
                    if extension_present != flagged_present:
                        if len(extension_flag_mismatches) < 100:
                            extension_flag_mismatches.append(
                                {
                                    "cluster_id": cluster_id,
                                    "edge_index": edge_index,
                                    "part_index": part.index,
                                    "secondary_flags": part.secondary_flags,
                                    "extension_hex": part.extension.hex(),
                                }
                            )
                        counts["extension_flag_mismatches"] += 1
                    if not part.extension:
                        counts["parts_without_extension"] += 1
                        continue
                    counts["parts_with_extension"] += 1
                    counts["extension_bytes"] += len(part.extension)
                    try:
                        attribute_stream = decode_geometry_attribute_stream(
                            part.extension, part.flags
                        )
                        attributes = decode_tagged_attributes(attribute_stream)
                        header = decode_tagged_attribute_header(attribute_stream)
                    except PsfError as error:
                        counts["invalid_extensions"] += 1
                        if len(invalid_extensions) < 100:
                            invalid_extensions.append(
                                {
                                    "cluster_id": cluster_id,
                                    "edge_index": edge_index,
                                    "part_index": part.index,
                                    "extension_hex": part.extension.hex(),
                                    "error": str(error),
                                }
                            )
                        continue
                    first_tag_types[header.type_id] += 1
                    first_tag_continuation[(header.type_id, header.has_next)] += 1
                    tag_sequences[tuple(item.type_id for item in attributes)] += 1
                    part_simple_speed_limits: list[int] = []
                    for attribute in attributes:
                        all_tag_types[attribute.type_id] += 1
                        tag_sizes[attribute.type_id][len(attribute.data)] += 1
                        if attribute.type_id == 1:
                            speed_limit = decode_simple_speed_limit(attribute)
                            part_simple_speed_limits.append(speed_limit.value)
                            edge_simple_speed_limits.append(speed_limit.value)
                            simple_speed_limit_values[speed_limit.value] += 1
                            simple_speed_limit_by_direction[
                                (direction.mode, speed_limit.value)
                            ] += 1
                        elif attribute.type_id == GeometryAttributeType.EXTENDED_SPEED_LIMIT:
                            extended_speed = decode_extended_speed_limit(attribute)
                            counts["extended_speed_limit_values"] += 1
                            extended_speed_limit_values[extended_speed.value] += 1
                            extended_speed_limit_subtypes[extended_speed.subtype] += 1
                            extended_speed_limit_directions[
                                (extended_speed.a_to_b, extended_speed.b_to_a)
                            ] += 1
                            extended_speed_limit_sources[
                                extended_speed.source_selector
                            ] += 1
                            extended_speed_limit_pair_counts[
                                extended_speed.pair_count
                            ] += 1
                        if attribute.type_id in selected_payloads:
                            selected_payloads[attribute.type_id][attribute.data.hex()] += 1
                        if attribute.type_id == GeometryAttributeType.NUMBER_OF_LANES:
                            lane_counts = decode_number_of_lanes(attribute)
                            edge_has_number_of_lanes = True
                            counts["number_of_lanes_values"] += 1
                            number_of_lanes_pairs[
                                (lane_counts.at_node_a, lane_counts.at_node_b)
                            ] += 1
                            number_of_lanes_by_direction[
                                (
                                    direction.mode,
                                    lane_counts.at_node_a,
                                    lane_counts.at_node_b,
                                )
                            ] += 1
                        elif attribute.type_id == GeometryAttributeType.SIMPLE_PASSING_RESTRICTION:
                            decode_simple_passing_restriction(attribute)
                            edge_has_simple_passing = True
                            counts["simple_passing_restriction_markers"] += 1
                        elif attribute.type_id == GeometryAttributeType.EXTENDED_PASSING_RESTRICTION:
                            passing = decode_extended_passing_restriction_header(attribute)
                            edge_has_extended_passing = True
                            counts["extended_passing_restrictions"] += 1
                            extended_passing_headers[
                                (
                                    passing.a_to_b,
                                    passing.b_to_a,
                                    passing.has_detailed_records,
                                    passing.detailed_record_count,
                                )
                            ] += 1
                        elif attribute.type_id == GeometryAttributeType.LANES:
                            lanes = decode_lanes(attribute)
                            edge_has_lanes = True
                            counts["lanes_attributes"] += 1
                            counts["lane_records"] += len(lanes.records)
                            lanes_record_counts[len(lanes.records)] += 1
                            lanes_low_nibbles[lanes.header_low_nibble] += 1
                            for record in lanes.records:
                                lane_byte_0_low_nibbles[record.byte_0_low_nibble] += 1
                                lane_byte_0_flags[
                                    (record.byte_0_bit_4, record.byte_0_bit_5)
                                ] += 1
                                lane_byte_1_low_nibble_codes[
                                    record.byte_1_low_nibble_code
                                ] += 1
                                lane_byte_2_high_nibble_codes[
                                    record.byte_2_high_nibble_code
                                ] += 1
                                lane_byte_3_low_3_bits_codes[
                                    record.byte_3_low_3_bits_code
                                ] += 1
                                lane_firmware_category_masks[
                                    record.firmware_category_mask
                                ] += 1
                    if part_simple_speed_limits:
                        counts["parts_with_simple_speed_limit"] += 1
                        counts["simple_speed_limit_values"] += len(
                            part_simple_speed_limits
                        )
                        if len(part_simple_speed_limits) > 1:
                            counts["parts_with_multiple_simple_speed_limits"] += 1
                    if header.has_next:
                        continued_extension_lengths[header.type_id][len(attribute_stream)] += 1
                    else:
                        terminal_single_tag_lengths[header.type_id][len(attribute_stream)] += 1
                    item = {
                        "cluster_id": cluster_id,
                        "edge_index": edge_index,
                        "edge_id": (cluster_id << 8) | edge_index,
                        "part_index": part.index,
                        "part_flags": part.flags,
                        "direction": direction.mode,
                        "descriptor_hex": descriptor.hex(),
                        "secondary_flags": part.secondary_flags,
                        "first_tag_type": header.type_id,
                        "first_tag_has_next": header.has_next,
                        "attribute_stream_hex": attribute_stream.hex(),
                        "tag_types": [attribute.type_id for attribute in attributes],
                        "tag_sizes": [len(attribute.data) for attribute in attributes],
                        "simple_speed_limit_values": part_simple_speed_limits,
                        "extension_hex": part.extension.hex(),
                    }
                    if len(tag_samples[header.type_id]) < 10:
                        tag_samples[header.type_id].append(item)
                    if sample_limit == 0 or samples_written < sample_limit:
                        samples.write(json.dumps(item, sort_keys=True) + "\n")
                        samples_written += 1
                if edge_simple_speed_limits:
                    counts["edges_with_simple_speed_limit"] += 1
                    if len(edge_simple_speed_limits) > 1:
                        counts["edges_with_multiple_simple_speed_limit_values"] += 1
                    simple_speed_limit_edge_min_candidates[
                        min(edge_simple_speed_limits)
                    ] += 1
                edge_min_speed: int | str = (
                    min(edge_simple_speed_limits)
                    if edge_simple_speed_limits
                    else "none"
                )
                for bit_index in automotive.active_bit_indices:
                    automotive_bits_by_edge_min_speed[
                        (bit_index, edge_min_speed)
                    ] += 1
                edge_secondary_flag_456_tuples[
                    tuple(
                        int(any(part.secondary_flags & (1 << bit) for part in parts))
                        for bit in (4, 5, 6)
                    )
                ] += 1
                counts["urban_edges"] += int(
                    decode_urban_road(part.secondary_flags for part in parts)
                )
                counts["edges_with_number_of_lanes"] += int(edge_has_number_of_lanes)
                counts["edges_with_simple_passing_restriction"] += int(
                    edge_has_simple_passing
                )
                counts["edges_with_extended_passing_restriction"] += int(
                    edge_has_extended_passing
                )
                counts["edges_with_lanes_attributes"] += int(edge_has_lanes)
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress(
                    "decode-progress",
                    clusters=ordinal,
                    total=len(order),
                    edges=counts["edges"],
                    parts=counts["parts"],
                    invalid=counts["invalid_extensions"],
                )
    sample_temporary.replace(sample_path)

    valid = counts["extension_flag_mismatches"] == 0 and counts["invalid_extensions"] == 0
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "raw-profile-validated" if valid else "validation-failed",
        "input": {"path": str(psf.resolve()), "size": psf.stat().st_size, "sha256": _sha256(psf)},
        "scope": {
            "confirmed_semantics": {
                "descriptor_byte_3_bit_0": "static/base A-to-B allowed",
                "descriptor_byte_3_bit_1": "static/base B-to-A allowed",
                "direction_firmware_consumer_ghidra_va": "0x002e1c9c",
                "geometry_tag_1": "simple speed-limit value",
                "speed_limit_storage_firmware_consumer_ghidra_va": "0x002f0484",
                "speed_limit_api_firmware_consumer_ghidra_va": "0x002e3a34",
                "speed_limit_unit": "not yet independently proven",
                "geometry_tags_13_to_16": (
                    "EXTT_NUMBER_OF_LANES, EXTT_SIMPLE_PASSING_RESTRICTION, "
                    "EXTT_EXTENDED_PASSING_RESTRICTION, EXTT_LANES"
                ),
                "lane_and_passing_firmware_consumers_ghidra_va": [
                    "0x0097f054",
                    "0x0097cb48",
                ],
                "descriptor_bytes_7_8_low_13_bits": (
                    "base extended-automotive attribute mask"
                ),
                "automotive_attributes_firmware_consumer_ghidra_va": "0x008ce240",
                "geometry_part_secondary_flag_bit_5": (
                    "edge urban flag, OR across parts; decoder VA 0x002f0484, "
                    "consumer VA 0x013e5be8"
                ),
            },
            "unlabeled": "all other descriptor bytes and geometry attribute tag payloads",
            "time_dependent_note": "extended restrictions may further restrict a statically allowed direction",
        },
        "counts": dict(counts),
        "direction_modes": _counter(direction_modes),
        "descriptor_byte_distributions": {
            str(index): _counter(counter) for index, counter in enumerate(descriptor_bytes)
        },
        "descriptor_byte_3_high_bit_distribution": _counter(descriptor_byte3_high_bits),
        "automotive_attributes": {
            "base_mask_distribution": _counter(automotive_base_masks),
            "active_bit_edge_counts": _counter(automotive_active_bits),
            "descriptor_byte_1_low7_distribution": _counter(
                descriptor_byte1_low7
            ),
            "active_bits_by_descriptor_byte_1_low7": _counter(
                automotive_bits_by_descriptor_byte1_low7
            ),
            "active_bits_by_edge_min_simple_speed": _counter(
                automotive_bits_by_edge_min_speed
            ),
            "dynamic_extension_marker_distribution": _counter(
                automotive_dynamic_extension
            ),
            "bit_meanings": "retained as mask pending per-bit public enum proof",
        },
        "direction_by_descriptor_byte_1_low7": _counter(direction_by_byte1_low7),
        "secondary_flags": _counter(secondary_flags),
        "secondary_flag_active_part_counts": _counter(secondary_flag_active_bits),
        "edge_secondary_flag_bits_4_5_6_tuple_counts": _counter(
            edge_secondary_flag_456_tuples
        ),
        "urban": {
            "edge_count": counts["urban_edges"],
            "source": "OR of geometry-part secondary flag bit 5 (0x20)",
            "decoder_firmware_ghidra_va": "0x002f0484",
            "consumer_firmware_ghidra_va": "0x013e5be8",
        },
        "first_tag_types": _counter(first_tag_types),
        "first_tag_continuation": _counter(first_tag_continuation),
        "all_tag_types": _counter(all_tag_types),
        "tag_sequences": _counter(tag_sequences),
        "tag_size_distributions": {
            str(tag): _counter(sizes) for tag, sizes in sorted(tag_sizes.items())
        },
        "simple_speed_limit": {
            "storage": "geometry tagged attribute type 1, payload byte 1",
            "unit": None,
            "value_distribution": _counter(simple_speed_limit_values),
            "value_by_static_direction": _counter(simple_speed_limit_by_direction),
            "edge_min_candidate_distribution": _counter(
                simple_speed_limit_edge_min_candidates
            ),
            "edge_min_candidate_note": (
                "raw minimum over tag-1 values on an edge; firmware applies an "
                "additional configured geometry-class mask before selecting its minimum"
            ),
        },
        "extended_speed_limit": {
            "storage": (
                "geometry tag 2: packed size, direction/subtype, value, condition/source fields"
            ),
            "firmware_consumers_ghidra_vas": ["0x0097e934", "0x0097e848", "0x0097e4a0"],
            "unit": None,
            "value_distribution": _counter(extended_speed_limit_values),
            "subtype_distribution": _counter(extended_speed_limit_subtypes),
            "direction_distribution": _counter(extended_speed_limit_directions),
            "source_selector_distribution": _counter(extended_speed_limit_sources),
            "condition_pair_count_distribution": _counter(extended_speed_limit_pair_counts),
            "subtype_0": "SLT_GENERAL (direct firmware diagnostic string)",
            "other_subtype_names": "pending enum-name proof; numeric values retained",
        },
        "number_of_lanes": {
            "storage": "geometry tagged attribute type 13, payload bytes 1 and 2",
            "node_a_node_b_distribution": _counter(number_of_lanes_pairs),
            "values_by_static_direction": _counter(number_of_lanes_by_direction),
        },
        "passing_restrictions": {
            "simple_storage": "payload-free geometry tag 14 marker",
            "extended_storage": "geometry tag 15",
            "extended_header_distribution": _counter(extended_passing_headers),
        },
        "lanes": {
            "storage": "geometry tag 16",
            "record_count_distribution": _counter(lanes_record_counts),
            "header_low_nibble_distribution": _counter(lanes_low_nibbles),
            "record_size_bytes": 4,
            "record_fields_firmware_evidence": "Ghidra VA 0x0097f054",
            "byte_0_low_nibble_distribution": _counter(lane_byte_0_low_nibbles),
            "byte_0_bit_4_bit_5_distribution": _counter(lane_byte_0_flags),
            "byte_1_low_nibble_code_distribution": _counter(
                lane_byte_1_low_nibble_codes
            ),
            "byte_2_high_nibble_code_distribution": _counter(
                lane_byte_2_high_nibble_codes
            ),
            "byte_3_low_3_bits_code_distribution": _counter(
                lane_byte_3_low_3_bits_codes
            ),
            "firmware_category_mask_distribution": _counter(
                lane_firmware_category_masks
            ),
            "category_mapping": (
                "stored codes 0..7 mapped by the direct firmware switch; "
                "codes above 7 require the map runtime lookup table and remain null"
            ),
            "public_enum_names": "pending independent API/name proof",
        },
        "selected_tag_payload_distributions": {
            str(type_id): {
                "enum": GeometryAttributeType(type_id).name,
                "unique_payloads": len(payloads),
                "top_payloads": dict(payloads.most_common(256)),
            }
            for type_id, payloads in selected_payloads.items()
        },
        "terminal_single_tag_lengths": {
            str(tag): _counter(lengths) for tag, lengths in sorted(terminal_single_tag_lengths.items())
        },
        "continued_extension_lengths": {
            str(tag): _counter(lengths) for tag, lengths in sorted(continued_extension_lengths.items())
        },
        "tag_samples": {str(tag): values for tag, values in sorted(tag_samples.items())},
        "validation": {
            "extension_presence_matches_secondary_flag_bit_7": counts["extension_flag_mismatches"] == 0,
            "extension_flag_mismatch_examples": extension_flag_mismatches,
            "all_first_tag_types_in_firmware_range_1_19": counts["invalid_extensions"] == 0,
            "invalid_extension_examples": invalid_extensions,
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
        f"{_sha256(report_path)}  {report_path.name}\n{_sha256(sample_path)}  {sample_path.name}\n",
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
        print(f"basic_road_attributes_profile: {error}", file=sys.stderr)
        return 1
    return 0 if report["status"] == "raw-profile-validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
