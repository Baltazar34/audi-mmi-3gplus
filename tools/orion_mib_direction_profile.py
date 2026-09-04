#!/usr/bin/env python3
"""Cross-tab raw Orion Property orientation values with MIB path direction."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys


ACCEPTED = {"high", "medium"}
ORIENTED_CLASSES = (
    "NumberOfLanesProperty",
    "PassingRestrictionProperty",
    "SpeedBumpsProperty",
    "SpeedLimitProperty",
)


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def endpoint_distance(point: dict[str, float], lon: float, lat: float) -> float:
    dx = (float(point["longitude"]) - lon) * math.cos(math.radians(lat))
    dy = float(point["latitude"]) - lat
    return dx * dx + dy * dy


def path_direction(
    original: dict[str, object], path_ids: list[int], mib: dict[int, dict[str, object]]
) -> tuple[str, list[int], list[str], str]:
    if original["from"] is not None:
        start = original["from"]
        start_basis = "from_node"
    else:
        start = original["centerline_geometry"]["parts"][0]["positions"][0]
        start_basis = "centerline_first_position"
    start_lon = float(start["longitude"])
    start_lat = float(start["latitude"])
    candidates: list[tuple[float, list[int], list[str]]] = []
    orders = [path_ids] if len(path_ids) == 1 else [path_ids, list(reversed(path_ids))]
    for ordered_ids in orders:
        first = mib[ordered_ids[0]]
        for first_traversal in ("a_to_b", "b_to_a"):
            current_node = int(
                first["to_node_id"]
                if first_traversal == "a_to_b"
                else first["from_node_id"]
            )
            traversals = [first_traversal]
            for edge_id in ordered_ids[1:]:
                edge = mib[edge_id]
                if int(edge["from_node_id"]) == current_node:
                    traversals.append("a_to_b")
                    current_node = int(edge["to_node_id"])
                elif int(edge["to_node_id"]) == current_node:
                    traversals.append("b_to_a")
                    current_node = int(edge["from_node_id"])
                else:
                    break
            if len(traversals) != len(ordered_ids):
                continue
            geometry = first["centerline"]
            start_point = geometry[0] if first_traversal == "a_to_b" else geometry[-1]
            candidates.append(
                (
                    endpoint_distance(start_point, start_lon, start_lat),
                    ordered_ids,
                    traversals,
                )
            )
    if not candidates:
        raise ValueError("bounded path edge set cannot form a connected chain")
    _, path_ids, traversals = min(candidates, key=lambda row: row[0])
    forward = all(
        bool(mib[edge_id]["travel_direction"][f"{traversal}_allowed"])
        for edge_id, traversal in zip(path_ids, traversals)
    )
    reverse = all(
        bool(
            mib[edge_id]["travel_direction"][
                "b_to_a_allowed" if traversal == "a_to_b" else "a_to_b_allowed"
            ]
        )
        for edge_id, traversal in zip(path_ids, traversals)
    )
    mode = "both" if forward and reverse else "forward" if forward else "reverse" if reverse else "closed"
    return mode, path_ids, traversals, start_basis


def run(
    bounded_path: Path,
    original_path: Path,
    property_path: Path,
    mib_path: Path,
    output: Path,
) -> dict[str, object]:
    originals = {
        (int(row["block_offset"]), int(row["edge_row"])): row
        for row in read_jsonl(original_path)
    }
    mib = {int(row["edge_id"]): row for row in read_jsonl(mib_path)}
    properties = {
        (int(row["block_offset"]), int(row["edge_row"])): row
        for row in read_jsonl(property_path)
    }
    rows: list[dict[str, object]] = []
    cross_tabs = {name: Counter() for name in ORIENTED_CLASSES}
    path_modes = Counter()
    start_bases = Counter()
    accepted = [
        row
        for row in read_jsonl(bounded_path)
        if row["graph_confidence"] in ACCEPTED
    ]
    for match in accepted:
        key = (int(match["block_offset"]), int(match["edge_row"]))
        original = originals[key]
        property_row = properties[key]
        path_ids = [int(value) for value in match["graph_match"]["edge_ids"]]
        mode, path_ids, traversals, start_basis = path_direction(original, path_ids, mib)
        path_modes[mode] += 1
        start_bases[start_basis] += 1
        orientation_values: dict[str, list[int]] = {}
        for class_name in ORIENTED_CLASSES:
            values = sorted(
                {
                    int(item["fields"]["Orientation"])
                    for part in property_row["property_lists"]
                    for item in part["properties"]
                    if item["class"] == class_name
                    and "Orientation" in item.get("fields", {})
                }
            )
            orientation_values[class_name] = values
            for value in values:
                cross_tabs[class_name][f"{value}->{mode}"] += 1
        rows.append(
            {
                "block_offset": key[0],
                "edge_row": key[1],
                "graph_confidence": match["graph_confidence"],
                "mib_path_mode_relative_to_original": mode,
                "mib_edge_ids": path_ids,
                "mib_edge_traversals": traversals,
                "original_start_basis": start_basis,
                "original_orientation_values": orientation_values,
            }
        )
    if len(rows) != len(accepted):
        raise ValueError("accepted direction rows were not joined exactly once")
    output.mkdir(parents=True, exist_ok=True)
    rows_path = output / "pairs.jsonl"
    report_path = output / "report.json"
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "accepted_paths": len(rows),
        "mib_path_modes_relative_to_original": dict(sorted(path_modes.items())),
        "original_start_bases": dict(sorted(start_bases.items())),
        "raw_orientation_to_mib_path_mode": {
            name: dict(sorted(counter.items())) for name, counter in cross_tabs.items()
        },
        "interpretation_boundary": (
            "Orientation values remain raw enums. A mapping may only be named after "
            "the same raw value consistently predicts a relative MIB path mode."
        ),
        "checks": {
            "all_accepted_paths_joined": len(rows) == len(accepted),
            "all_paths_topologically_connected": True,
            "no_orientation_enum_names_assigned": True,
        },
        "artifacts": {"pairs": rows_path.name},
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(rows_path)}  {rows_path.name}\n{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    print(
        f"orion-mib-direction paths={len(rows)} modes={dict(path_modes)} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bounded", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--properties", type=Path, required=True)
    parser.add_argument("--mib", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.bounded, args.original, args.properties, args.mib, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-direction error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
