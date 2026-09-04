#!/usr/bin/env python3
"""Profile MIB geometry flag bits against spatially matched Orion properties."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


def read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(matches_path: Path, mib_path: Path, output: Path) -> dict[str, object]:
    matches = read_jsonl(matches_path)
    mib = {int(row["edge_id"]): row for row in read_jsonl(mib_path)}
    profiles = {bit: Counter() for bit in range(8)}
    usable = 0
    skipped_mixed = 0
    for row in matches:
        if row["match_confidence"] != "high":
            continue
        target = int(row["original_properties"]["effective_baseline_tuple_or"][2])
        candidate_ids = [int(item["edge_id"]) for item in row["matched_mib_edges"]]
        if not candidate_ids:
            continue
        masks = [
            sum(
                1 << bit
                for bit in range(8)
                if any(
                    int(flag) & (1 << bit)
                    for flag in mib[edge_id]["geometry_part_secondary_flags"]
                )
            )
            for edge_id in candidate_ids
        ]
        usable += 1
        for bit in range(8):
            values = {(mask >> bit) & 1 for mask in masks}
            if len(values) != 1:
                profiles[bit]["mixed"] += 1
                skipped_mixed += 1
                continue
            value = next(iter(values))
            profiles[bit][f"{target} -> {value}"] += 1
    bit_reports: dict[str, object] = {}
    for bit, counts in profiles.items():
        compared = sum(value for key, value in counts.items() if key != "mixed")
        correct = counts["0 -> 0"] + counts["1 -> 1"]
        bit_reports[str(bit)] = {
            "confusion": dict(sorted(counts.items())),
            "compared": compared,
            "accuracy_if_direct": correct / compared if compared else None,
        }
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    report = {
        "schema_version": 1,
        "status": "complete",
        "scope": "high-confidence corridor matches only",
        "matches_input": str(matches_path),
        "mib_input": str(mib_path),
        "high_confidence_rows": sum(
            row["match_confidence"] == "high" for row in matches
        ),
        "usable_rows": usable,
        "mixed_bit_observations_skipped": skipped_mixed,
        "bits": bit_reports,
        "interpretation_boundary": (
            "A bit correlation is only a candidate. No formula may be emitted "
            "until topological identity and independent firmware semantics agree."
        ),
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
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
        print(f"audiurban-feature-profile error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
