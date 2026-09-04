#!/usr/bin/env python3
"""Run and cross-check the complete Basic road-attribute source stage."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from basic_graph_export import run as run_graph_export
from basic_dynamic_attributes_profile import run as run_dynamic_profile
from basic_road_attributes_profile import run as run_attribute_profile
from psf_decode import PsfError


SCHEMA_VERSION = 6


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"basic-road-attributes-stage stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    psf: Path,
    output: Path,
    sample_limit: int,
    transliterate_identifiers: frozenset[int],
) -> dict[str, object]:
    if sample_limit < 0:
        raise ValueError("sample limit must be zero or positive")
    output.mkdir(parents=True, exist_ok=True)

    _progress("profile")
    profile = run_attribute_profile(
        psf,
        output / "road_attribute_profile",
        sample_limit,
    )
    _progress("dynamic-profile")
    dynamic_profile = run_dynamic_profile(
        psf,
        output / "dynamic_attribute_profile",
        sample_limit,
    )
    _progress("graph")
    graph = run_graph_export(
        psf,
        output / "graph_export",
        sample_limit,
        transliterate_identifiers,
    )

    profile_counts = profile["counts"]
    graph_counts = graph["counts"]
    profile_directions = profile["direction_modes"]
    graph_semantics = graph["road_attribute_semantics"]
    dynamic_counts = dynamic_profile["counts"]
    checks = {
        "profile_validated": profile["status"] == "raw-profile-validated",
        "graph_validated": graph["status"] == "validated",
        "dynamic_profile_validated": (
            dynamic_profile["status"] == "dynamic-directory-validated"
        ),
        "edge_counts_match": profile_counts["edges"] == graph_counts["edges"],
        "part_counts_match": profile_counts["parts"]
        == graph_counts["geometry_parts"],
        "direction_distributions_match": profile_directions
        == graph_semantics["direction_modes"],
        "simple_speed_limit_counts_match": profile_counts[
            "simple_speed_limit_values"
        ]
        == graph_counts["simple_speed_limit_values"],
        "simple_speed_limit_distributions_match": profile["simple_speed_limit"][
            "value_distribution"
        ]
        == graph_semantics["simple_speed_limit_value_distribution"],
        "extended_speed_limit_counts_match": profile_counts[
            "extended_speed_limit_values"
        ]
        == graph_counts["extended_speed_limit_values"],
        "extended_speed_limit_distributions_match": profile[
            "extended_speed_limit"
        ]["value_distribution"]
        == graph_semantics["extended_speed_limit"]["value_distribution"],
        "number_of_lanes_counts_match": profile_counts["number_of_lanes_values"]
        == graph_counts["number_of_lanes_values"],
        "simple_passing_counts_match": profile_counts[
            "simple_passing_restriction_markers"
        ]
        == graph_counts["simple_passing_restriction_markers"],
        "extended_passing_counts_match": profile_counts[
            "extended_passing_restrictions"
        ]
        == graph_counts["extended_passing_restrictions"],
        "lanes_attribute_counts_match": profile_counts["lanes_attributes"]
        == graph_counts["lanes_attributes"],
        "lane_record_counts_match": profile_counts["lane_records"]
        == graph_counts["lane_records"],
        "lane_category_mask_distributions_match": profile["lanes"][
            "firmware_category_mask_distribution"
        ]
        == graph_semantics["lane_firmware_category_mask_distribution"],
        "automotive_base_mask_distributions_match": profile[
            "automotive_attributes"
        ]["base_mask_distribution"]
        == graph_semantics["automotive_attributes"]["base_mask_distribution"],
        "automotive_active_bit_counts_match": profile["automotive_attributes"][
            "active_bit_edge_counts"
        ]
        == graph_semantics["automotive_attributes"]["active_bit_edge_counts"],
        "urban_edge_counts_match": profile["urban"]["edge_count"]
        == graph_semantics["urban"]["edge_count"],
        "dynamic_marker_edge_counts_match": dynamic_counts["dynamic_marker_edges"]
        == profile["automotive_attributes"]["dynamic_extension_marker_distribution"]["True"],
        "dynamic_directory_cluster_counts_match": dynamic_counts[
            "clusters_with_directory"
        ]
        == graph_counts["clusters_with_dynamic_directory"],
        "dynamic_directory_entry_counts_match": dynamic_counts["directory_entries"]
        == graph_counts["dynamic_directory_entries"],
        "dynamic_type_5_record_counts_match": dynamic_counts.get(
            "type_5_records", 0
        )
        == graph_counts["dynamic_type_5_records"],
        "dynamic_type_3_record_counts_match": dynamic_counts.get(
            "type_3_records", 0
        )
        == graph_counts["dynamic_type_3_records"],
    }
    valid = all(checks.values())
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated" if valid else "validation-failed",
        "input": profile["input"],
        "checks": checks,
        "counts": {
            "clusters": profile_counts["clusters"],
            "edges": profile_counts["edges"],
            "urban_edges": profile["urban"]["edge_count"],
            "geometry_parts": profile_counts["parts"],
            "tagged_attribute_parts": profile_counts["parts_with_extension"],
            "edges_with_simple_speed_limit": profile_counts[
                "edges_with_simple_speed_limit"
            ],
            "simple_speed_limit_values": profile_counts[
                "simple_speed_limit_values"
            ],
            "extended_speed_limit_values": profile_counts[
                "extended_speed_limit_values"
            ],
            "number_of_lanes_values": profile_counts["number_of_lanes_values"],
            "simple_passing_restriction_markers": profile_counts[
                "simple_passing_restriction_markers"
            ],
            "extended_passing_restrictions": profile_counts[
                "extended_passing_restrictions"
            ],
            "lanes_attributes": profile_counts["lanes_attributes"],
            "lane_records": profile_counts["lane_records"],
            "dynamic_marker_edges": dynamic_counts["dynamic_marker_edges"],
            "clusters_with_dynamic_directory": dynamic_counts[
                "clusters_with_directory"
            ],
            "dynamic_directory_entries": dynamic_counts["directory_entries"],
            "dynamic_type_5_records": dynamic_counts.get("type_5_records", 0),
            "dynamic_type_3_records": dynamic_counts.get("type_3_records", 0),
        },
        "confirmed_source_contract": {
            "static_travel_direction": (
                "descriptor byte 3 bits 0/1; firmware VA 0x002e1c9c"
            ),
            "simple_speed_limit": (
                "geometry tag 1 payload byte; firmware VAs 0x002f0484 and 0x002e3a34"
            ),
            "simple_speed_limit_unit": None,
            "simple_speed_limit_unit_status": "not independently proven",
            "extended_speed_limit": (
                "geometry tag 2 direction/subtype/value/condition fields; "
                "firmware VAs 0x0097e934, 0x0097e848 and 0x0097e4a0"
            ),
            "number_of_lanes": (
                "geometry tag 13 node-A/node-B counts; firmware VA 0x0097f054"
            ),
            "passing_restrictions": (
                "geometry tags 14/15; firmware VA 0x0097cb48"
            ),
            "lanes": (
                "geometry tag 16 four-byte records with consumed bit/nibble fields and "
                "direct 0..7 category switch; firmware VA 0x0097f054"
            ),
            "extended_automotive_attributes": (
                "descriptor bytes 7/8 low-13-bit mask; firmware VA 0x008ce240"
            ),
            "urban": (
                "OR of geometry-part secondary flag bit 5; decoder VA 0x002f0484 "
                "writes edge object +0x16c, consumed by VA 0x013e5be8"
            ),
            "dynamic_attribute_directory": (
                "topology u24le pointer + typed directory; firmware VA 0x014a67e0"
            ),
            "dynamic_type_5_numeric_override": (
                "edge-keyed four-byte records; firmware VA 0x014a69e8; public name/unit pending"
            ),
            "dynamic_type_3_edge_condition_source": (
                "edge/selector/u16 condition records plus year/month/day/weekday/time fields; "
                "firmware VAs 0x014a9858 and 0x014aa33c..0x014aa5f8"
            ),
            "raw_provenance_retained": True,
        },
        "pending_semantics": [
            "type-3 runtime timezone/query-mask inputs and final adapter direction evaluation",
            "remaining extended-speed subtype enum names and value unit proof",
            "public enum names and map-version lookup values above 7 inside lane records",
            "per-bit enum meanings for the automotive mask and vehicle-class restrictions",
            "AudiUrban source-semantic mapping (distinct subset of Urban in original Orion)",
        ],
        "artifacts": {
            "profile_report": "road_attribute_profile/report.json",
            "dynamic_profile_report": "dynamic_attribute_profile/report.json",
            "graph_report": "graph_export/report.json",
            "graph_nodes": "graph_export/nodes.jsonl",
            "graph_edges": "graph_export/edges.jsonl",
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    child_reports = [
        output / "road_attribute_profile" / "report.json",
        output / "dynamic_attribute_profile" / "report.json",
        output / "graph_export" / "report.json",
    ]
    checksum_lines = [f"{_sha256(report_path)}  {report_path.name}"]
    checksum_lines.extend(
        f"{_sha256(path)}  {path.relative_to(output)}" for path in child_reports
    )
    (output / "CHECKSUMS.sha256").write_text(
        "\n".join(checksum_lines) + "\n",
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
        help="bounded JSONL output after every input record is validated; 0 emits all",
    )
    parser.add_argument(
        "--transliterate-identifier",
        action="append",
        type=lambda value: int(value, 0),
        default=[],
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        identifiers = frozenset(args.transliterate_identifier)
        if any(not 0 <= identifier < 0x80 for identifier in identifiers):
            raise ValueError("transliteration identifier outside low-7-bit range")
        report = run(args.psf, args.output, args.sample_limit, identifiers)
    except (OSError, PsfError, TypeError, ValueError) as error:
        print(f"run_basic_road_attributes_stage: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "output": str(args.output),
                "counts": report["counts"],
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
