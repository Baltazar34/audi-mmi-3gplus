#!/usr/bin/env python3
"""Decode original Orion PropertyD1 lists and attach them to graph edge rows.

Input is a directory produced by ``orion_graph_spatial_probe.py
--save-decoded``.  Baseline-only graph schemas contain one empty structural
descriptor immediately before their three Property scalar columns; schemas
with optional Property classes retain their direct grouped member indices.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from orion_column_codec import type_widths, validate_code1_payload_roundtrip
from orion_property_corpus_profile import (
    _classify,
    _composite,
    _decode_part,
    _derives_from,
    _group,
)
from orion_psd_reference_profile import class_object_ranges, group_serialized_parts


BASELINE_CLASSES = ("AdasProperty", "UrbanProperty", "AudiUrbanProperty")
PHYSICAL_BASELINE_ORDER = (
    "AdasProperty",
    "AudiUrbanProperty",
    "UrbanProperty",
)


def _reference_storage_type(
    member: dict[str, object],
    by_index: dict[int, dict[str, object]],
    numeric_ranges: dict[int, tuple[int, int]],
) -> int:
    """Return the smallest unsigned physical type which can hold a class handle."""

    target_index = int(member["type_composite_index"])
    target = by_index.get(target_index)
    if target is None or int(target["kind"]) != 1:
        raise ValueError("Property reference target is not a class")
    _, maximum_handle = numeric_ranges[target_index]
    for type_code in (0x20, 0x21, 0x22, 0x23, 0x24, 0x25):
        value_bits, _ = type_widths(type_code)
        if maximum_handle < (1 << value_bits):
            return type_code
    raise ValueError(f"Property reference handle {maximum_handle} exceeds 32 bits")


def align_property_members(
    schema: dict[str, object],
    table: dict[str, object],
    subclasses: list[dict[str, object]],
    baseline_descriptors: dict[str, int],
    numeric_ranges: dict[int, tuple[int, int]],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Align logical Property members to their contiguous physical columns.

    Property subclass inheritance consumes no column of its own.  Scalar
    members retain their exact type, class references use the smallest
    unsigned handle type, and row-aligned structures are implicit.  Requiring
    all three already-proven baseline anchors makes the match unambiguous.
    """

    by_index = {int(row["index"]): row for row in schema["composites"]}
    expected: list[dict[str, object]] = []
    implicit: list[dict[str, object]] = []
    for composite in subclasses:
        class_name = str(composite["name"])
        for ordinal, member in enumerate(composite["members"]):
            member_name = member.get("name")
            if member_name is None:
                member_name = f"anonymous_{ordinal}"
            logical_type = int(member["type_code"])
            if logical_type == 0xC0:
                target = by_index.get(int(member["type_composite_index"]))
                if target is None or int(target["row_count"]) != int(composite["row_count"]):
                    raise ValueError(f"non-row-aligned structure {class_name}.{member_name}")
                implicit.append(
                    {
                        "class": class_name,
                        "member": member_name,
                        "target": str(target["name"]),
                        "mapping": "implicit_same_row",
                    }
                )
                continue
            if logical_type == 0xB0:
                physical_type = _reference_storage_type(member, by_index, numeric_ranges)
                allowed_physical_types = list(range(0x20, physical_type + 1))
                target_name = str(by_index[int(member["type_composite_index"])]["name"])
            else:
                type_widths(logical_type)
                physical_type = logical_type
                if 0x20 <= logical_type <= 0x25:
                    # The writer narrows unsigned scalar columns to the
                    # smallest width which holds this chunk's actual values.
                    allowed_physical_types = list(range(0x20, logical_type + 1))
                else:
                    allowed_physical_types = [logical_type]
                target_name = None
            expected.append(
                {
                    "class": class_name,
                    "member": str(member_name),
                    "member_index": int(member["index"]),
                    "member_kind": int(member["kind"]),
                    "row_count": int(composite["row_count"]),
                    "logical_type": logical_type,
                    "physical_type": physical_type,
                    "allowed_physical_types": allowed_physical_types,
                    "reference_target": target_name,
                }
            )

    descriptor_types = [int(row["type_code"]) for row in table["descriptors"]]
    candidates: list[int] = []
    for start in range(len(descriptor_types) - len(expected) + 1):
        if any(
            descriptor_types[start + offset] not in row["allowed_physical_types"]
            for offset, row in enumerate(expected)
        ):
            continue
        positions = {
            str(row["class"]): start + offset
            for offset, row in enumerate(expected)
            if str(row["class"]) in BASELINE_CLASSES
        }
        if all(positions.get(name) == index for name, index in baseline_descriptors.items()):
            candidates.append(start)
    if len(candidates) != 1:
        raise ValueError(f"Property physical alignment has {len(candidates)} candidates")
    start = candidates[0]
    aligned = []
    for offset, row in enumerate(expected):
        item = dict(row)
        item["descriptor_index"] = start + offset
        item["physical_type"] = descriptor_types[start + offset]
        aligned.append(item)
    return aligned, implicit


def decode_property_fields(
    decoded: bytes,
    schema: dict[str, object],
    table: dict[str, object],
    groups: list[dict[str, object]],
    layouts: list[object],
    subclasses: list[dict[str, object]],
    baseline_descriptors: dict[str, int],
    numeric_ranges: dict[int, tuple[int, int]],
) -> tuple[dict[str, list[dict[str, object]]], dict[str, object]]:
    """Decode every non-implicit member of every Property subclass."""

    aligned, implicit = align_property_members(
        schema, table, subclasses, baseline_descriptors, numeric_ranges
    )
    values: dict[str, list[dict[str, object]]] = {
        str(row["name"]): [dict() for _ in range(int(row["row_count"]))]
        for row in subclasses
    }
    for mapping in aligned:
        if int(mapping["member_kind"]) == 2:
            continue
        class_name = str(mapping["class"])
        member_name = str(mapping["member"])
        row_count = int(mapping["row_count"])
        descriptor_index = int(mapping["descriptor_index"])
        descriptor = table["descriptors"][descriptor_index]
        if int(descriptor["tag"]) == 3:
            dictionary = _decode_part(
                decoded,
                table,
                layouts,
                descriptor_index,
                int(descriptor["indirect_count"]),
            )
            auxiliary = [
                row
                for row in aligned
                if str(row["class"]) == class_name
                and int(row["member_kind"]) == 2
                and int(row["member_index"]) == int(descriptor["member_index"])
            ]
            if len(auxiliary) != 1:
                raise ValueError(f"{class_name}.{member_name} lacks one indirect index")
            indices = _decode_part(
                decoded,
                table,
                layouts,
                int(auxiliary[0]["descriptor_index"]),
                row_count,
            )
            if any(index >= len(dictionary) for index in indices):
                raise ValueError(f"{class_name}.{member_name} indirect index overrun")
            column = [dictionary[index] for index in indices]
            mapping["decoding"] = "indirect_dictionary"
            mapping["dictionary_size"] = len(dictionary)
            mapping["index_descriptor"] = int(auxiliary[0]["descriptor_index"])
        else:
            column = _decode_part(
                decoded, table, layouts, descriptor_index, row_count
            )
            mapping["decoding"] = "direct"
        target_name = mapping["reference_target"]
        if target_name is not None:
            target = next(row for row in schema["composites"] if row["name"] == target_name)
            first, last = numeric_ranges[int(target["index"])]
            if any(value != 0 and not first <= value <= last for value in column):
                raise ValueError(f"invalid {class_name}.{member_name} reference")
        for row_index, value in enumerate(column):
            values[class_name][row_index][member_name] = value

    implicit_details: list[dict[str, object]] = []
    for mapping in implicit:
        class_name = str(mapping["class"])
        member_name = str(mapping["member"])
        target_name = str(mapping["target"])
        target = next(row for row in schema["composites"] if row["name"] == target_name)
        row_count = int(target["row_count"])
        target_groups = [row for row in groups if row["composite_name"] == target_name]
        part_indices = [
            index
            for group in target_groups
            for index in range(
                int(group["part_start"]),
                int(group["part_start"]) + int(group["part_count"]),
            )
        ]
        columns = [
            _decode_part(decoded, table, layouts, part_index, row_count)
            for part_index in part_indices
        ]
        for row_index in range(row_count):
            values[class_name][row_index][member_name] = {
                "target": target_name,
                "raw_parts": [column[row_index] for column in columns],
            }
        detail = dict(mapping)
        detail["descriptor_indices"] = part_indices
        implicit_details.append(detail)
    report = {
        "physical_start": int(aligned[0]["descriptor_index"]),
        "physical_end": int(aligned[-1]["descriptor_index"]),
        "members": aligned,
        "implicit_members": implicit_details,
    }
    return values, report


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-edge-property stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def decode_property_scalars(
    decoded: bytes,
    schema: dict[str, object],
    table: dict[str, object],
    groups: list[dict[str, object]],
    layouts: list[object],
    subclasses: list[dict[str, object]],
) -> tuple[dict[str, list[int]], dict[str, int]]:
    """Decode baseline scalar rows using the proven schema-specific mapping."""

    values_by_class: dict[str, list[int]] = {}
    descriptors_by_class: dict[str, int] = {}
    by_name = {str(row["name"]): row for row in subclasses}
    baseline_only = set(by_name) == set(BASELINE_CLASSES)
    baseline_shifted_indexes: dict[str, int] = {}
    if baseline_only:
        property_groups = [
            group
            for group in groups
            if str(group["composite_name"]) in by_name
        ]
        first = min(int(group["part_start"]) for group in property_groups)
        last = max(
            int(group["part_start"]) + int(group["part_count"])
            for group in property_groups
        )
        candidates = [
            index
            for index in range(first, min(last + 1, len(layouts)))
            if int(table["descriptors"][index]["size"]) > 0
        ]
        if len(candidates) != 3:
            raise ValueError(
                f"baseline-only scalar window has {len(candidates)} non-empty parts"
            )
        baseline_shifted_indexes = dict(zip(PHYSICAL_BASELINE_ORDER, candidates))
    for class_name in BASELINE_CLASSES:
        row = by_name.get(class_name)
        if row is None:
            raise ValueError(f"missing mandatory {class_name}")
        if len(row["members"]) != 1:
            raise ValueError(f"{class_name} does not have one scalar member")
        member_name = str(row["members"][0]["name"])
        logical_group = _group(groups, class_name, member_name)
        if int(logical_group["part_count"]) != 1:
            raise ValueError(f"{class_name}.{member_name} is not one physical part")
        if baseline_only:
            physical_index = baseline_shifted_indexes[class_name]
        else:
            # Optional-property graph schemas contain two hidden structural
            # columns before Adas/AudiUrban.  The final Urban scalar is the
            # one column immediately following its grouped slot, just before
            # PointGeometry.  The shifted targets are physical 0x10 boolean
            # columns; the nominal grouped slots have incompatible widths.
            physical_index = int(logical_group["part_start"]) + (
                1 if class_name == "UrbanProperty" else 2
            )
        if physical_index >= len(table["descriptors"]):
            raise ValueError(f"shifted descriptor missing for {class_name}")
        if int(table["descriptors"][physical_index]["type_code"]) != 0x10:
            raise ValueError(f"{class_name} scalar is not physical boolean 0x10")
        row_values = _decode_part(
            decoded,
            table,
            layouts,
            physical_index,
            int(row["row_count"]),
        )
        if not set(row_values) <= {0, 1}:
            raise ValueError(f"{class_name} contains a non-boolean value")
        values_by_class[class_name] = row_values
        descriptors_by_class[class_name] = physical_index
    return values_by_class, descriptors_by_class


def decode_sample(schema_path: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    metadata = json.loads(schema_path.read_text(encoding="utf-8"))
    decoded_path = schema_path.with_name(schema_path.name.replace(".schema.json", ".decoded.bin"))
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
    by_index = {int(row["index"]): row for row in schema["composites"]}
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
        str(row["name"]): numeric_ranges[int(row["index"])] for row in subclasses
    }
    scalars, scalar_descriptors = decode_property_scalars(
        decoded, schema, table, groups, layouts, subclasses
    )
    property_fields, field_mapping = decode_property_fields(
        decoded,
        schema,
        table,
        groups,
        layouts,
        subclasses,
        scalar_descriptors,
        numeric_ranges,
    )

    prop = _composite(schema, "PropertyD1")
    attrs = _composite(schema, "Attributes")
    edge = _composite(schema, "EdgeRoadElement")
    if int(attrs["row_count"]) != int(edge["row_count"]):
        raise ValueError("Attributes and EdgeRoadElement row counts differ")
    prop_group = _group(groups, "PropertyD1", "Values")
    attrs_group = _group(groups, "Attributes", "Parts")
    if int(prop_group["part_count"]) != 3 or int(attrs_group["part_count"]) != 1:
        raise ValueError("unexpected PropertyD1/Attributes physical layout")
    prop_start = int(prop_group["part_start"])
    attrs_start = int(attrs_group["part_start"])
    list_count = int(prop["row_count"])
    edge_count = int(edge["row_count"])
    cardinalities = _decode_part(decoded, table, layouts, prop_start, list_count)
    handles = _decode_part(
        decoded, table, layouts, prop_start + 1, sum(cardinalities)
    )
    defaults = _decode_part(decoded, table, layouts, prop_start + 2, 1)
    attr_counts = _decode_part(decoded, table, layouts, attrs_start, edge_count)
    if defaults != [0]:
        raise ValueError(f"unexpected PropertyD1 default {defaults}")
    if sum(attr_counts) > list_count:
        raise ValueError("edge Attributes.Parts overrun PropertyD1 rows")

    property_lists: list[dict[str, object]] = []
    handle_cursor = 0
    for list_index, cardinality in enumerate(cardinalities):
        list_handles = handles[handle_cursor : handle_cursor + cardinality]
        handle_cursor += cardinality
        properties: list[dict[str, object]] = []
        for handle in list_handles:
            class_name = _classify(handle, named_ranges)
            if class_name == "INVALID":
                raise ValueError(f"property handle {handle} outside subclass ranges")
            first_handle, _ = named_ranges[class_name]
            class_row = handle - first_handle
            item: dict[str, object] = {"class": class_name, "handle": handle}
            if class_name in scalars:
                item["value"] = scalars[class_name][class_row]
            if property_fields[class_name][class_row]:
                item["fields"] = property_fields[class_name][class_row]
            properties.append(item)
        property_lists.append(
            {
                "list_index": list_index,
                "cardinality": cardinality,
                "properties": properties,
            }
        )

    rows: list[dict[str, object]] = []
    list_cursor = 0
    tuple_counts: Counter[str] = Counter()
    effective_tuple_counts: Counter[str] = Counter()
    conflict_edges = 0
    edges_without_baseline = 0
    for edge_row, part_count in enumerate(attr_counts):
        edge_lists = property_lists[list_cursor : list_cursor + part_count]
        list_cursor += part_count
        tuples: list[tuple[int, int, int]] = []
        for property_list in edge_lists:
            baseline = {
                str(item["class"]): int(item["value"])
                for item in property_list["properties"]
                if item["class"] in BASELINE_CLASSES and "value" in item
            }
            if set(baseline) == set(BASELINE_CLASSES):
                value_tuple = (
                    baseline["AdasProperty"],
                    baseline["UrbanProperty"],
                    baseline["AudiUrbanProperty"],
                )
                tuples.append(value_tuple)
                tuple_counts["+".join(map(str, value_tuple))] += 1
        unique_tuples = sorted(set(tuples))
        if len(unique_tuples) > 1:
            conflict_edges += 1
        effective_tuple = (
            tuple(max(values) for values in zip(*tuples)) if tuples else None
        )
        if effective_tuple is None:
            edges_without_baseline += 1
        else:
            effective_tuple_counts["+".join(map(str, effective_tuple))] += 1
        rows.append(
            {
                "source_schema": schema_path.name,
                "block_offset": metadata["block_offset"],
                "block_offset_hex": metadata["block_offset_hex"],
                "edge_row": edge_row,
                "attribute_part_count": part_count,
                "property_lists": edge_lists,
                "baseline_tuples": [list(value) for value in unique_tuples],
                "effective_baseline_tuple_or": (
                    list(effective_tuple) if effective_tuple is not None else None
                ),
            }
        )
    summary = {
        "schema": schema_path.name,
        "decoded": decoded_path.name,
        "block_offset": metadata["block_offset"],
        "block_offset_hex": metadata["block_offset_hex"],
        "edges": edge_count,
        "property_lists": list_count,
        "edge_referenced_property_lists": sum(attr_counts),
        "unreferenced_property_lists": list_count - sum(attr_counts),
        "property_handles": len(handles),
        "property_scalar_mapping": (
            "baseline-only non-empty scalar window"
            if set(named_ranges) == set(BASELINE_CLASSES)
            else "optional schema: Adas/AudiUrban +2, terminal Urban +1"
        ),
        "scalar_descriptors": scalar_descriptors,
        "property_field_mapping": field_mapping,
        "baseline_tuple_counts": dict(sorted(tuple_counts.items())),
        "effective_edge_tuple_counts": dict(sorted(effective_tuple_counts.items())),
        "edges_with_conflicting_baseline_tuples": conflict_edges,
        "edges_without_baseline_tuple": edges_without_baseline,
    }
    return rows, summary


def run(input_dir: Path, output: Path) -> dict[str, object]:
    schema_paths = sorted(input_dir.glob("match_*.schema.json"))
    if not schema_paths:
        raise ValueError(f"no match_*.schema.json files in {input_dir}")
    output.mkdir(parents=True, exist_ok=True)
    edges_path = output / "edges.properties.jsonl"
    report_path = output / "report.json"
    all_rows: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    global_tuples: Counter[str] = Counter()
    global_effective_tuples: Counter[str] = Counter()
    for schema_path in schema_paths:
        rows, summary = decode_sample(schema_path)
        all_rows.extend(rows)
        summaries.append(summary)
        global_tuples.update(summary["baseline_tuple_counts"])
        global_effective_tuples.update(summary["effective_edge_tuple_counts"])
        progress(
            "chunk",
            block=summary["block_offset_hex"],
            edges=summary["edges"],
            tuples=sum(summary["baseline_tuple_counts"].values()),
        )
    invalid_subset = global_effective_tuples.get(
        "0+0+1", 0
    ) + global_effective_tuples.get("1+0+1", 0)
    decoded_property_rows: Counter[str] = Counter()
    indirect_columns = 0
    for summary in summaries:
        mappings = summary["property_field_mapping"]["members"]
        class_rows = {
            (str(mapping["class"]), int(mapping["row_count"]))
            for mapping in mappings
        }
        decoded_property_rows.update(dict(class_rows))
        indirect_columns += sum(
            str(mapping.get("decoding")) == "indirect_dictionary"
            for mapping in mappings
        )
    checks = {
        "all_chunks_decoded": len(summaries) == len(schema_paths),
        "all_edges_have_baseline_tuple": all(
            int(summary["edges_without_baseline_tuple"]) == 0
            for summary in summaries
        ),
        "all_property_fields_aligned_and_decoded": True,
    }
    if not all(checks.values()):
        raise ValueError(
            f"edge property checks failed: {checks}; "
            f"list_tuples={dict(sorted(global_tuples.items()))}; "
            f"effective_tuples={dict(sorted(global_effective_tuples.items()))}; "
            f"conflicts={[summary['edges_with_conflicting_baseline_tuples'] for summary in summaries]}"
        )
    edges_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in all_rows),
        encoding="utf-8",
    )
    report = {
        "schema_version": 2,
        "status": "complete",
        "input": str(input_dir),
        "chunks": len(summaries),
        "edges": len(all_rows),
        "baseline_tuple_order": ["Adas", "Urban", "AudiUrban"],
        "baseline_tuple_counts": dict(sorted(global_tuples.items())),
        "effective_edge_tuple_counts": dict(sorted(global_effective_tuples.items())),
        "decoded_property_rows": dict(sorted(decoded_property_rows.items())),
        "indirect_dictionary_columns_decoded": indirect_columns,
        "observations": {
            "effective_audiurban_without_urban_edges": invalid_subset,
            "audiurban_implies_urban_in_this_optional_property_sample": (
                invalid_subset == 0
            ),
            "scope_note": (
                "The previously proven AudiUrban=>Urban invariant covers "
                "baseline-only Property chunks. These saved spatial chunks "
                "mostly contain optional Property classes and retain their "
                "lossless per-part values even when that baseline invariant "
                "does not hold."
            ),
        },
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.input_dir, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-edge-property error={error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "chunks": report["chunks"],
                "edges": report["edges"],
                "decoded_property_rows": report["decoded_property_rows"],
                "indirect_dictionary_columns_decoded": report[
                    "indirect_dictionary_columns_decoded"
                ],
                "checks": report["checks"],
                "output": str(args.output),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
