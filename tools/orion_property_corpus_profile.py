#!/usr/bin/env python3
"""Profile PropertyD1 lists and Property subclasses across an Orion ATLAS."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
import lzma
from pathlib import Path
import struct
import sys
import zlib

from orion_column_codec import (
    type_widths,
    unpack_code1_values,
    validate_code1_payload_roundtrip,
)
from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    _read_name,
    class_object_ranges,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
)


SCHEMA_VERSION = 2


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-property-corpus stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _composite(schema: dict[str, object], name: str) -> dict[str, object]:
    for composite in schema["composites"]:
        if composite["name"] == name:
            return composite
    raise ValueError(f"missing composite {name}")


def _group(
    groups: list[dict[str, object]], composite: str, member: str
) -> dict[str, object]:
    for group in groups:
        if group["composite_name"] == composite and group["member_name"] == member:
            return group
    raise ValueError(f"missing group {composite}.{member}")


def _derives_from(
    composite: dict[str, object], base_index: int, by_index: dict[int, dict[str, object]]
) -> bool:
    current = composite
    seen: set[int] = set()
    while int(current["kind"]) == 1 and int(current["index"]) not in seen:
        index = int(current["index"])
        if index == base_index:
            return True
        seen.add(index)
        parent = int(current["base_index"])
        if parent == 0xFFFF or parent not in by_index:
            return False
        current = by_index[parent]
    return False


def _decode_part(
    decoded: bytes,
    table: dict[str, object],
    layouts: list[object],
    part_index: int,
    count: int,
) -> list[int]:
    descriptor = table["descriptors"][part_index]
    layout = layouts[part_index]
    payload = decoded[layout.payload_offset : layout.payload_offset + layout.payload_size]
    if int(descriptor["tag"]) == 1:
        constant = unpack_code1_values(int(descriptor["type_code"]), payload, 1)
        return constant * count
    _, storage_bits = type_widths(int(descriptor["type_code"]))
    used_size = (count * storage_bits + 7) // 8
    if len(payload) < used_size:
        raise ValueError(
            f"part {part_index} needs {used_size} bytes for {count} values, "
            f"has {len(payload)}"
        )
    return unpack_code1_values(
        int(descriptor["type_code"]), payload[:used_size], count
    )


def _classify(handle: int, ranges: dict[str, tuple[int, int]]) -> str:
    for name, (first, last) in ranges.items():
        if first <= handle <= last:
            return name
    return "INVALID"


def _member_signature(composite: dict[str, object]) -> str:
    members = [
        (
            member["name"],
            int(member["type_code"]),
            member.get("type_composite_index"),
            (
                int(member["optional_flag"])
                if member.get("optional_flag") is not None
                else None
            ),
        )
        for member in composite["members"]
    ]
    return json.dumps(members, separators=(",", ":"))


def profile_file(atlas: Path, block_limit: int) -> dict[str, object]:
    file_size = atlas.stat().st_size
    block_offset = 0
    block_count = 0
    decoded_chunks = 0
    graph_chunks = 0
    failures = 0
    edge_total = 0
    property_list_total = 0
    property_handle_total = 0
    class_rows: Counter[str] = Counter()
    class_references: Counter[str] = Counter()
    list_patterns: Counter[str] = Counter()
    list_cardinalities: Counter[int] = Counter()
    attribute_part_cardinalities: Counter[int] = Counter()
    unreferenced_property_lists: Counter[int] = Counter()
    class_member_signatures: dict[str, Counter[str]] = defaultdict(Counter)
    scalar_windows: Counter[str] = Counter()
    baseline_scalar_chunks = 0
    baseline_scalar_failures = 0
    baseline_value_rows: dict[str, Counter[int]] = defaultdict(Counter)
    baseline_reference_values: dict[str, Counter[int]] = defaultdict(Counter)
    baseline_reference_tuples: Counter[tuple[int, int, int]] = Counter()
    samples: list[dict[str, object]] = []

    with atlas.open("rb") as source:
        while block_offset < file_size and (block_limit == 0 or block_count < block_limit):
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
                    names = {str(row["name"]) for row in schema["composites"]}
                    if not {"PropertyD1", "Property", "EdgeRoadElement"} <= names:
                        continue
                    table = parse_exact_column_table(decoded, schema)
                    if table is None or any(
                        int(code) != 1 for code in table["compression_codes"]
                    ):
                        raise ValueError(
                            f"graph chunk at 0x{block_offset:x} lacks exact code-1 table"
                        )
                    groups = group_serialized_parts(schema, table["descriptors"])
                    layouts = validate_code1_payload_roundtrip(
                        decoded,
                        int(schema["data_offset"]),
                        table["descriptors"],
                        table["compression_codes"],
                    )
                    by_index = {
                        int(row["index"]): row for row in schema["composites"]
                    }
                    base = _composite(schema, "Property")
                    base_index = int(base["index"])
                    subclasses = [
                        row
                        for row in schema["composites"]
                        if int(row["kind"]) == 1
                        and int(row["index"]) != base_index
                        and _derives_from(row, base_index, by_index)
                    ]
                    numeric_ranges = class_object_ranges(schema)
                    named_ranges = {
                        str(row["name"]): numeric_ranges[int(row["index"])]
                        for row in subclasses
                    }
                    prop = _composite(schema, "PropertyD1")
                    attrs = _composite(schema, "Attributes")
                    prop_group = _group(groups, "PropertyD1", "Values")
                    attrs_group = _group(groups, "Attributes", "Parts")
                    if int(prop_group["part_count"]) != 3:
                        raise ValueError("PropertyD1.Values is not a three-part list")
                    if int(attrs_group["part_count"]) != 1:
                        raise ValueError("Attributes.Parts is not a direct cardinality")
                    prop_start = int(prop_group["part_start"])
                    attrs_start = int(attrs_group["part_start"])
                    list_count = int(prop["row_count"])
                    edge_count = int(attrs["row_count"])
                    try:
                        cardinalities = _decode_part(
                            decoded, table, layouts, prop_start, list_count
                        )
                        handles = _decode_part(
                            decoded, table, layouts, prop_start + 1, sum(cardinalities)
                        )
                        defaults = _decode_part(
                            decoded, table, layouts, prop_start + 2, 1
                        )
                        attr_counts = _decode_part(
                            decoded, table, layouts, attrs_start, edge_count
                        )
                    except ValueError as error:
                        raise ValueError(
                            f"property decode failed at block=0x{block_offset:x} "
                            f"chunk={chunk_index} prop_part={prop_start} "
                            f"attrs_part={attrs_start}: {error}"
                        ) from error
                    attribute_expansion = sum(attr_counts)
                    if defaults != [0] or attribute_expansion > list_count:
                        raise ValueError(
                            "property list/attribute cardinality contract failed "
                            f"at block=0x{block_offset:x} chunk={chunk_index} "
                            f"defaults={defaults} attribute_sum={attribute_expansion} "
                            f"lists={list_count} attrs_part={attrs_start}"
                        )
                    unreferenced_property_lists[list_count - attribute_expansion] += 1

                    cursor_handle = 0
                    for cardinality in cardinalities:
                        values = handles[cursor_handle : cursor_handle + cardinality]
                        cursor_handle += cardinality
                        classes = tuple(_classify(value, named_ranges) for value in values)
                        if "INVALID" in classes:
                            raise ValueError("property handle outside Property subclasses")
                        list_patterns["+".join(classes)] += 1
                        list_cardinalities[cardinality] += 1
                    for value in handles:
                        class_references[_classify(value, named_ranges)] += 1
                    for row in subclasses:
                        name = str(row["name"])
                        class_rows[name] += int(row["row_count"])
                        class_member_signatures[name][_member_signature(row)] += 1
                    attribute_part_cardinalities.update(attr_counts)

                    property_group_parts = [
                        group
                        for group in groups
                        if str(group["composite_name"]) in named_ranges
                    ]
                    if property_group_parts:
                        first = min(int(group["part_start"]) for group in property_group_parts)
                        last = max(
                            int(group["part_start"]) + int(group["part_count"])
                            for group in property_group_parts
                        )
                        window = tuple(
                            (
                                int(table["descriptors"][index]["type_code"]),
                                int(table["descriptors"][index]["size"]),
                            )
                            for index in range(first, last)
                        )
                        scalar_windows[json.dumps(window, separators=(",", ":"))] += 1
                    else:
                        window = ()

                    baseline_names = (
                        "AdasProperty",
                        "AudiUrbanProperty",
                        "UrbanProperty",
                    )
                    if set(named_ranges) == set(baseline_names) and property_group_parts:
                        # The graph schemas place one empty structural descriptor
                        # immediately before these three scalar columns.  The old
                        # sequential grouper therefore includes that empty part and
                        # assigns the final Urban bit column to PointGeometry.  For
                        # baseline-only schemas the three non-empty one-bit columns
                        # are unambiguous by class row count and original order.
                        first = min(
                            int(group["part_start"]) for group in property_group_parts
                        )
                        last = max(
                            int(group["part_start"]) + int(group["part_count"])
                            for group in property_group_parts
                        )
                        candidate_indexes = [
                            index
                            for index in range(first, min(last + 1, len(layouts)))
                            if int(table["descriptors"][index]["size"]) > 0
                        ]
                        decoded_baseline: dict[str, list[int]] = {}
                        if len(candidate_indexes) == 3:
                            try:
                                for class_name, part_index in zip(
                                    baseline_names, candidate_indexes
                                ):
                                    class_row = next(
                                        row
                                        for row in subclasses
                                        if row["name"] == class_name
                                    )
                                    row_count = int(class_row["row_count"])
                                    descriptor = table["descriptors"][part_index]
                                    _, storage_bits = type_widths(
                                        int(descriptor["type_code"])
                                    )
                                    if storage_bits != 1:
                                        raise ValueError("baseline scalar is not one bit")
                                    decoded_baseline[class_name] = _decode_part(
                                        decoded,
                                        table,
                                        layouts,
                                        part_index,
                                        row_count,
                                    )
                            except (StopIteration, ValueError):
                                decoded_baseline = {}
                        if len(decoded_baseline) == 3:
                            baseline_scalar_chunks += 1
                            for class_name, values in decoded_baseline.items():
                                baseline_value_rows[class_name].update(values)
                            for handle in handles:
                                class_name = _classify(handle, named_ranges)
                                first_handle, _ = named_ranges[class_name]
                                baseline_reference_values[class_name][
                                    decoded_baseline[class_name][handle - first_handle]
                                ] += 1
                            cursor_handle = 0
                            for cardinality in cardinalities:
                                list_handles = handles[
                                    cursor_handle : cursor_handle + cardinality
                                ]
                                cursor_handle += cardinality
                                values_by_class: dict[str, int] = {}
                                for handle in list_handles:
                                    class_name = _classify(handle, named_ranges)
                                    if class_name in values_by_class:
                                        values_by_class = {}
                                        break
                                    first_handle, _ = named_ranges[class_name]
                                    values_by_class[class_name] = decoded_baseline[
                                        class_name
                                    ][handle - first_handle]
                                if set(values_by_class) == set(baseline_names):
                                    baseline_reference_tuples[
                                        (
                                            values_by_class["AdasProperty"],
                                            values_by_class["UrbanProperty"],
                                            values_by_class["AudiUrbanProperty"],
                                        )
                                    ] += 1
                        else:
                            baseline_scalar_failures += 1

                    graph_chunks += 1
                    edge_total += edge_count
                    property_list_total += list_count
                    property_handle_total += len(handles)
                    if len(samples) < 24:
                        samples.append(
                            {
                                "block_offset": block_offset,
                                "block_name": block_name,
                                "chunk_index": chunk_index,
                                "edges": edge_count,
                                "property_lists": list_count,
                                "property_handles": len(handles),
                                "class_rows": {
                                    str(row["name"]): int(row["row_count"])
                                    for row in subclasses
                                },
                                "physical_scalar_window": [list(value) for value in window],
                            }
                        )
            block_offset += block_size
            block_count += 1
            if block_count and block_count % 1000 == 0:
                _progress(
                    "scan",
                    blocks=block_count,
                    decoded=decoded_chunks,
                    graph=graph_chunks,
                )

    baseline_pattern = "AdasProperty+UrbanProperty+AudiUrbanProperty"
    baseline_count = list_patterns[baseline_pattern]
    baseline_reference_counts = {
        name: class_references[name]
        for name in ("AdasProperty", "UrbanProperty", "AudiUrbanProperty")
    }
    checks = {
        "graph_chunks_found": graph_chunks > 0,
        "all_property_handles_classified": "INVALID" not in class_references,
        "attribute_parts_do_not_overrun_property_lists": all(
            delta >= 0 for delta in unreferenced_property_lists
        ),
        "list_cardinalities_expand_to_handles": sum(
            cardinality * count for cardinality, count in list_cardinalities.items()
        )
        == property_handle_total,
        "property_patterns_cover_every_list": sum(list_patterns.values())
        == property_list_total,
        "mandatory_property_reference_counts_match": len(
            set(baseline_reference_counts.values())
        )
        == 1,
        "baseline_reference_tuples_cover_decoded_references": (
            sum(baseline_reference_tuples.values())
            == baseline_reference_values["AdasProperty"].total()
            == baseline_reference_values["UrbanProperty"].total()
            == baseline_reference_values["AudiUrbanProperty"].total()
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"corpus property checks failed: {checks}")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "source": {
            "path": str(atlas),
            "size": file_size,
            "sha256": _sha256(atlas),
            "read_only": True,
        },
        "scan": {
            "blocks": block_count,
            "decoded_chunks": decoded_chunks,
            "decode_failures": failures,
            "graph_property_chunks": graph_chunks,
        },
        "totals": {
            "edges": edge_total,
            "property_lists": property_list_total,
            "property_handles": property_handle_total,
        },
        "baseline_contract": {
            "ordered_classes": baseline_pattern.split("+"),
            "matching_lists": baseline_count,
            "nonmatching_special_lists": property_list_total - baseline_count,
            "mandatory_class_reference_counts": baseline_reference_counts,
            "writer_policy": (
                "emit the ordered baseline triple; keep optional classes separate"
            ),
        },
        "baseline_scalar_values": {
            "decoded_chunks": baseline_scalar_chunks,
            "failed_chunks": baseline_scalar_failures,
            "class_row_value_counts": {
                name: dict(sorted(counter.items()))
                for name, counter in sorted(baseline_value_rows.items())
            },
            "referenced_value_counts": {
                name: dict(sorted(counter.items()))
                for name, counter in sorted(baseline_reference_values.items())
            },
            "referenced_tuple_order": ["Adas", "Urban", "AudiUrban"],
            "referenced_tuple_counts": {
                "+".join(str(value) for value in values): count
                for values, count in sorted(baseline_reference_tuples.items())
            },
            "scope": "chunks containing only Adas/AudiUrban/Urban Property subclasses",
        },
        "distributions": {
            "property_list_cardinalities": dict(sorted(list_cardinalities.items())),
            "attribute_part_cardinalities": dict(
                sorted(attribute_part_cardinalities.items())
            ),
            "unreferenced_property_lists_per_chunk": dict(
                sorted(unreferenced_property_lists.items())
            ),
            "ordered_property_class_patterns": dict(list_patterns.most_common()),
            "property_subclass_rows": dict(class_rows.most_common()),
            "property_subclass_references": dict(class_references.most_common()),
            "physical_property_scalar_windows": dict(scalar_windows.most_common()),
        },
        "property_class_member_signatures": {
            name: dict(counter.most_common())
            for name, counter in sorted(class_member_signatures.items())
        },
        "samples": samples,
        "checks": checks,
        "note": (
            "Physical scalar windows are retained by ordinal because their ordering "
            "is not yet proven to be identical to logical member declaration order."
        ),
    }


def run(atlas: Path, output: Path, block_limit: int) -> dict[str, object]:
    _progress("start", atlas=atlas, block_limit=block_limit)
    report = profile_file(atlas, block_limit)
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n", encoding="ascii"
    )
    _progress(
        "complete",
        graph=report["scan"]["graph_property_chunks"],
        lists=report["totals"]["property_lists"],
        handles=report["totals"]["property_handles"],
        checks="all-pass",
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--block-limit", type=int, default=0)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    if args.block_limit < 0:
        parser.error("--block-limit must not be negative")
    try:
        report = run(args.atlas, args.output, args.block_limit)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-property-corpus error={error}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
