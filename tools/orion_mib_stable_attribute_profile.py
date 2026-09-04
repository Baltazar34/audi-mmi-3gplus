#!/usr/bin/env python3
"""Compare stable attributes on accepted Orion-to-MIB topology paths."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from orion_mib_spatial_match import read_jsonl


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(matches_path: Path, mib_path: Path, output: Path) -> dict[str, object]:
    accepted = [
        row
        for row in read_jsonl(matches_path)
        if row["graph_confidence"] in {"high", "medium"}
    ]
    mib = {int(row["edge_id"]): row for row in read_jsonl(mib_path)}
    property_pairs = {
        "SpeedLimitProperty": Counter(),
        "NumberOfLanesProperty": Counter(),
        "PassingRestrictionProperty": Counter(),
    }
    automotive_bits = {bit: Counter() for bit in range(16)}
    direction_by_audiurban: Counter[str] = Counter()
    for row in accepted:
        classes = {
            str(item["class"])
            for property_list in row["original_properties"]["property_lists"]
            for item in property_list["properties"]
        }
        path = [mib[int(edge_id)] for edge_id in row["graph_match"]["edge_ids"]]
        targets = {
            "SpeedLimitProperty": any(edge["simple_speed_limit_values"] for edge in path)
            or any(2 in edge["geometry_attribute_type_ids"] for edge in path),
            "NumberOfLanesProperty": any(edge["has_number_of_lanes"] for edge in path),
            "PassingRestrictionProperty": any(edge["has_passing_restriction"] for edge in path),
        }
        for name, target in targets.items():
            property_pairs[name][f"{int(name in classes)} -> {int(target)}"] += 1
        audiurban = int(row["original_properties"]["effective_baseline_tuple_or"][2])
        automotive_or = 0
        for edge in path:
            automotive_or |= int(edge["automotive"]["base_mask"])
        for bit in range(16):
            automotive_bits[bit][f"{audiurban} -> {(automotive_or >> bit) & 1}"] += 1
        modes = sorted({str(edge["travel_direction"]["mode"]) for edge in path})
        direction_by_audiurban[f"{audiurban} -> {'+'.join(modes)}"] += 1

    attributes = {}
    for name, counts in property_pairs.items():
        total = sum(counts.values())
        correct = counts["0 -> 0"] + counts["1 -> 1"]
        attributes[name] = {
            "confusion": dict(sorted(counts.items())),
            "direct_presence_accuracy": correct / total if total else None,
        }
    automotive = {}
    for bit, counts in automotive_bits.items():
        total = sum(counts.values())
        correct = counts["0 -> 0"] + counts["1 -> 1"]
        automotive[str(bit)] = {
            "confusion": dict(sorted(counts.items())),
            "accuracy_if_direct_audiurban": correct / total if total else None,
        }
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report = {
        "schema_version": 1,
        "status": "complete",
        "scope": "bounded graph high+medium paths",
        "accepted_paths": len(accepted),
        "property_presence": attributes,
        "automotive_bits_vs_audiurban": automotive,
        "travel_direction_modes_by_audiurban": dict(sorted(direction_by_audiurban.items())),
        "interpretation_boundary": (
            "Presence correlations are qualification evidence only; semantic equivalence "
            "requires value decoding and a larger accepted identity corpus."
        ),
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(report_path)}  {report_path.name}\n", encoding="ascii"
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matches", type=Path)
    parser.add_argument("mib", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.matches, args.mib, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-attribute-profile error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
