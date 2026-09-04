#!/usr/bin/env python3
"""Prove PropertyD1/Attributes cardinalities in an extracted Orion graph chunk."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from orion_column_codec import (
    unpack_code1_values,
    validate_code1_payload_roundtrip,
)
from orion_psd_reference_profile import (
    class_object_ranges,
    parse_exact_column_table,
    parse_logical_schema,
)


SCHEMA_VERSION = 1


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _group(document: dict[str, object], composite: str, member: str) -> dict[str, object]:
    for group in document["groups"]:
        if group["composite_name"] == composite and group["member_name"] == member:
            return group
    raise ValueError(f"missing group {composite}.{member}")


def _composite(schema: dict[str, object], name: str) -> dict[str, object]:
    for composite in schema["composites"]:
        if composite["name"] == name:
            return composite
    raise ValueError(f"missing composite {name}")


def _decode(
    binary: bytes,
    table: dict[str, object],
    layouts: list[object],
    descriptor_index: int,
    count: int,
) -> list[int]:
    descriptor = table["descriptors"][descriptor_index]
    layout = layouts[descriptor_index]
    return unpack_code1_values(
        int(descriptor["type_code"]),
        binary[layout.payload_offset : layout.payload_offset + layout.payload_size],
        count,
    )


def profile(schema_document: dict[str, object], binary: bytes) -> dict[str, object]:
    schema = parse_logical_schema(binary)
    if schema is None:
        raise ValueError("decoded binary has no logical schema")
    if schema != schema_document["schema"]:
        raise ValueError("schema JSON and decoded binary differ")
    table = parse_exact_column_table(binary, schema)
    if table is None:
        raise ValueError("decoded binary has no exact column table")
    layouts = validate_code1_payload_roundtrip(
        binary,
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    ranges = class_object_ranges(schema)
    property_base = _composite(schema, "Property")
    property_index = int(property_base["index"])

    def derives_from_property(composite: dict[str, object]) -> bool:
        current = composite
        seen: set[int] = set()
        by_index = {int(row["index"]): row for row in schema["composites"]}
        while int(current["kind"]) == 1 and int(current["index"]) not in seen:
            index = int(current["index"])
            if index == property_index:
                return True
            seen.add(index)
            base = int(current["base_index"])
            if base == 0xFFFF or base not in by_index:
                return False
            current = by_index[base]
        return False

    property_classes = [
        composite
        for composite in schema["composites"]
        if int(composite["kind"]) == 1
        and int(composite["index"]) != property_index
        and derives_from_property(composite)
    ]
    property_ranges = {
        str(row["name"]): list(ranges[int(row["index"])]) for row in property_classes
    }
    property_min = min(value[0] for value in property_ranges.values())
    property_max = max(value[1] for value in property_ranges.values())

    property_d1 = _composite(schema, "PropertyD1")
    attributes = _composite(schema, "Attributes")
    node = _composite(schema, "NodeRoadElement")
    prop_group = _group(schema_document, "PropertyD1", "Values")
    attrs_group = _group(schema_document, "Attributes", "Parts")
    edge_attrs_group = _group(schema_document, "EdgeRoadElement", "Attributes")
    node_point_group = _group(schema_document, "NodeRoadElement", "PointGeometry")
    if int(prop_group["part_count"]) != 3:
        raise ValueError("PropertyD1.Values does not have three physical parts")
    if int(attrs_group["part_count"]) != 1:
        raise ValueError("Attributes.Parts does not have one physical part")

    property_list_count = int(property_d1["row_count"])
    edge_count = int(attributes["row_count"])
    node_count = int(node["row_count"])
    prop_start = int(prop_group["part_start"])
    attr_start = int(attrs_group["part_start"])
    node_point_start = int(node_point_group["part_start"])
    property_cardinalities = _decode(
        binary, table, layouts, prop_start, property_list_count
    )
    property_handles = _decode(
        binary, table, layouts, prop_start + 1, sum(property_cardinalities)
    )
    property_default = _decode(binary, table, layouts, prop_start + 2, 1)
    attribute_part_cardinalities = _decode(
        binary, table, layouts, attr_start, edge_count
    )
    point_geometry_handles = _decode(
        binary, table, layouts, node_point_start, node_count
    )

    handle_class_counts = {name: 0 for name in property_ranges}
    for handle in property_handles:
        for name, (first, last) in property_ranges.items():
            if first <= handle <= last:
                handle_class_counts[name] += 1
                break
    point_target = _composite(schema, "PointGeometry")
    point_range = ranges[int(point_target["index"])]
    checks = {
        "edge_attributes_binding_is_implicit": int(edge_attrs_group["part_count"])
        == 0,
        "node_point_geometry_is_direct": int(node_point_group["part_count"]) == 1,
        "node_point_geometry_is_complete_permutation": sorted(point_geometry_handles)
        == list(range(point_range[0], point_range[1] + 1)),
        "property_cardinality_sum_matches_flattened_handles": sum(
            property_cardinalities
        )
        == len(property_handles),
        "every_property_handle_targets_property_subclass": all(
            property_min <= value <= property_max for value in property_handles
        ),
        "attribute_parts_expand_to_property_lists": sum(attribute_part_cardinalities)
        == property_list_count,
        "property_default_is_zero": property_default == [0],
    }
    if not all(checks.values()):
        raise ValueError(f"property layout checks failed: {checks}")
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "counts": {
            "edges": edge_count,
            "nodes": node_count,
            "property_lists": property_list_count,
            "property_handles": len(property_handles),
            "minimum_properties_per_list": min(property_cardinalities),
            "maximum_properties_per_list": max(property_cardinalities),
            "attribute_parts": sum(attribute_part_cardinalities),
        },
        "property_class_handle_ranges": property_ranges,
        "property_handle_class_counts": handle_class_counts,
        "checks": checks,
        "writer_contract": {
            "Attributes.Parts": "one cardinality per EdgeRoadElement; flattened count equals PropertyD1 rows",
            "PropertyD1.Values.part0": "one property cardinality per PropertyD1 row",
            "PropertyD1.Values.part1": "flattened global Property subclass handles",
            "PropertyD1.Values.part2": "optional/default uint32 part",
            "EdgeRoadElement.Attributes": "implicit one-to-one structure binding",
            "NodeRoadElement.PointGeometry": "direct global PointGeometry handle",
        },
    }


def run(schema_path: Path, binary_path: Path, output: Path) -> dict[str, object]:
    print("orion-property-layout stage=read", file=sys.stderr, flush=True)
    document = json.loads(schema_path.read_text(encoding="utf-8"))
    binary = binary_path.read_bytes()
    report = profile(document, binary)
    report["sources"] = {
        "schema": {"path": str(schema_path), "sha256": _sha256(schema_path)},
        "binary": {"path": str(binary_path), "sha256": _sha256(binary_path)},
    }
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n", encoding="ascii"
    )
    print(
        "orion-property-layout stage=complete "
        f"lists={report['counts']['property_lists']} "
        f"handles={report['counts']['property_handles']} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("schema", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.schema, args.binary, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-property-layout error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
