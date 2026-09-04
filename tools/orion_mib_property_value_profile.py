#!/usr/bin/env python3
"""Profile decoded Orion Property values against accepted MIB graph paths."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


ACCEPTED = {"high", "medium"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def original_values(edge: dict[str, object], class_name: str, member: str) -> list[int]:
    return sorted(
        {
            int(item["fields"][member])
            for part in edge["property_lists"]
            for item in part["properties"]
            if item["class"] == class_name and member in item.get("fields", {})
        }
    )


def presence_category(original: list[object], mib: list[object]) -> str:
    return f"{int(bool(original))}->{int(bool(mib))}"


def run(
    bounded_path: Path,
    property_path: Path,
    mib_path: Path,
    output: Path,
) -> dict[str, object]:
    properties = {
        (int(row["block_offset"]), int(row["edge_row"])): row
        for row in read_jsonl(property_path)
    }
    mib = {int(row["edge_id"]): row for row in read_jsonl(mib_path)}
    pairs: list[dict[str, object]] = []
    presence = {name: Counter() for name in ("speed", "lanes", "passing")}
    speed_exact = Counter()
    lane_overlap = Counter()
    confidence_summary: dict[str, Counter[str]] = {}
    for match in read_jsonl(bounded_path):
        if match["graph_confidence"] not in ACCEPTED:
            continue
        key = (int(match["block_offset"]), int(match["edge_row"]))
        original = properties[key]
        path_edges = [mib[int(edge_id)] for edge_id in match["graph_match"]["edge_ids"]]
        original_speed = original_values(original, "SpeedLimitProperty", "Speed")
        original_lanes = original_values(original, "NumberOfLanesProperty", "Normal")
        original_passing = original_values(
            original, "PassingRestrictionProperty", "Passing"
        )
        mib_speed = sorted(
            {
                int(value["value"])
                for edge in path_edges
                for value in edge["speed_limits"]
            }
        )
        mib_lanes = sorted(
            {
                int(value)
                for edge in path_edges
                for record in edge["number_of_lanes"]
                for value in (record["at_node_a"], record["at_node_b"])
                if value is not None
            }
        )
        mib_passing = [
            record
            for edge in path_edges
            for record in edge["passing_restrictions"]
        ]
        presence["speed"][presence_category(original_speed, mib_speed)] += 1
        presence["lanes"][presence_category(original_lanes, mib_lanes)] += 1
        presence["passing"][presence_category(original_passing, mib_passing)] += 1
        if original_speed and mib_speed:
            speed_exact[str(original_speed == mib_speed).lower()] += 1
        if original_lanes and mib_lanes:
            lane_overlap[str(bool(set(original_lanes) & set(mib_lanes))).lower()] += 1
        confidence = str(match["graph_confidence"])
        confidence_summary.setdefault(confidence, Counter())["paths"] += 1
        confidence_summary[confidence]["speed_either"] += int(
            bool(original_speed or mib_speed)
        )
        confidence_summary[confidence]["speed_both"] += int(
            bool(original_speed and mib_speed)
        )
        confidence_summary[confidence]["lanes_both"] += int(
            bool(original_lanes and mib_lanes)
        )
        confidence_summary[confidence]["passing_both"] += int(
            bool(original_passing and mib_passing)
        )
        pairs.append(
            {
                "block_offset": key[0],
                "block_offset_hex": match["block_offset_hex"],
                "edge_row": key[1],
                "graph_confidence": match["graph_confidence"],
                "mib_edge_ids": match["graph_match"]["edge_ids"],
                "original": {
                    "speed": original_speed,
                    "lanes_normal": original_lanes,
                    "passing": original_passing,
                },
                "mib": {
                    "speed": mib_speed,
                    "lanes": mib_lanes,
                    "passing": mib_passing,
                },
            }
        )
    expected_pairs = sum(
        row["graph_confidence"] in ACCEPTED for row in read_jsonl(bounded_path)
    )
    if len(pairs) != expected_pairs:
        raise ValueError(
            f"accepted bounded path join mismatch: expected {expected_pairs}, got {len(pairs)}"
        )
    output.mkdir(parents=True, exist_ok=True)
    pairs_path = output / "pairs.jsonl"
    report_path = output / "report.json"
    pairs_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in pairs),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "accepted_paths": len(pairs),
        "presence_transitions": {
            name: dict(sorted(counter.items())) for name, counter in presence.items()
        },
        "speed_exact_set_on_both_present": dict(sorted(speed_exact.items())),
        "lane_value_overlap_on_both_present": dict(sorted(lane_overlap.items())),
        "by_graph_confidence": {
            name: dict(sorted(counter.items()))
            for name, counter in sorted(confidence_summary.items())
        },
        "interpretation": (
            "Raw numeric values are compared without assigning enum names. "
            "Only exact speed sets are directly comparable; lane overlap is exploratory, "
            "and passing is retained as raw values plus MIB direction/detail records."
        ),
        "checks": {
            "all_accepted_paths_joined": len(pairs) == expected_pairs,
            "all_mib_path_edges_resolved": True,
            "raw_values_only_no_enum_guessing": True,
        },
        "artifacts": {"pairs": pairs_path.name},
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(pairs_path)}  {pairs_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    print(
        "orion-mib-property-values "
        f"paths={len(pairs)} speed_exact={dict(speed_exact)} "
        f"lane_overlap={dict(lane_overlap)} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bounded", type=Path, required=True)
    parser.add_argument("--properties", type=Path, required=True)
    parser.add_argument("--mib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.bounded, args.properties, args.mib, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-property-values error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
