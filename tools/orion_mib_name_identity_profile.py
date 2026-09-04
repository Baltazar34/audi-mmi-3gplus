#!/usr/bin/env python3
"""Cross-tab repeated Orion Item identifiers against MIB names/class codes."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
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


def set_relation(left: set[object], right: set[object]) -> str:
    if not left or not right:
        return "missing"
    if left == right:
        return "equal"
    if left & right:
        return "overlap"
    return "disjoint"


def run(
    identifiers_path: Path,
    mib_path: Path,
    corridor_paths: list[Path],
    output: Path,
) -> dict[str, object]:
    identifiers = {
        (int(row["block_offset"]), int(row["class_row"])): row
        for row in read_jsonl(identifiers_path)
        if row["class"] == "EdgeRoadElement"
    }
    mib = {int(row["edge_id"]): row for row in read_jsonl(mib_path)}
    rows: list[dict[str, object]] = []
    missing_mib_ids: set[int] = set()
    for path in corridor_paths:
        for match in read_jsonl(path):
            confidence = str(match["match_confidence"])
            if confidence not in {"high", "medium"}:
                continue
            key = (int(match["block_offset"]), int(match["edge_row"]))
            identifier = identifiers[key]
            selected_ids = [
                int(item["edge_id"])
                for item in match["matched_mib_edges"]
                if int(item["sample_votes_within_20m"]) > 0
            ]
            missing_mib_ids.update(edge_id for edge_id in selected_ids if edge_id not in mib)
            candidates = [mib[edge_id] for edge_id in selected_ids if edge_id in mib]
            names = sorted(
                {
                    str(name)
                    for candidate in candidates
                    for name in candidate["normalized_names"]
                }
            )
            class_codes = sorted(
                {
                    int(value)
                    for candidate in candidates
                    for field, value in candidate["endpoint_class_codes"].items()
                    if field in {"from", "to"} and value is not None
                }
            )
            rows.append(
                {
                    "block_offset": key[0],
                    "edge_row": key[1],
                    "match_confidence": confidence,
                    "identifier_u64": identifier["identifier_u64"],
                    "identifier_hex": identifier["identifier_hex"],
                    "mib_edge_ids": selected_ids,
                    "normalized_names": names,
                    "endpoint_class_codes": class_codes,
                }
            )
    rows.sort(key=lambda row: (int(row["block_offset"]), int(row["edge_row"])))
    by_identifier: dict[int, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        by_identifier[int(row["identifier_u64"])].append(row)
    repeated = {
        identifier: members
        for identifier, members in by_identifier.items()
        if len(members) > 1
    }
    name_relations = Counter()
    class_relations = Counter()
    mib_edge_relations = Counter()
    independent_name_relations = Counter()
    comparisons: list[dict[str, object]] = []
    for identifier, members in sorted(repeated.items()):
        for index, left in enumerate(members):
            for right in members[index + 1 :]:
                name_relation = set_relation(
                    set(left["normalized_names"]), set(right["normalized_names"])
                )
                class_relation = set_relation(
                    set(left["endpoint_class_codes"]), set(right["endpoint_class_codes"])
                )
                mib_edge_relation = set_relation(
                    set(left["mib_edge_ids"]), set(right["mib_edge_ids"])
                )
                name_relations[name_relation] += 1
                class_relations[class_relation] += 1
                mib_edge_relations[mib_edge_relation] += 1
                if mib_edge_relation == "disjoint":
                    independent_name_relations[name_relation] += 1
                comparisons.append(
                    {
                        "identifier_u64": identifier,
                        "identifier_hex": f"0x{identifier:016x}",
                        "left": left,
                        "right": right,
                        "name_relation": name_relation,
                        "shared_names": sorted(
                            set(left["normalized_names"]) & set(right["normalized_names"])
                        ),
                        "endpoint_class_relation": class_relation,
                        "mib_edge_relation": mib_edge_relation,
                    }
                )
    checks = {
        "corridor_keys_resolve_to_identifiers": True,
        "all_selected_mib_ids_resolved": not missing_mib_ids,
        "profile_keys_unique": len(rows)
        == len({(row["block_offset"], row["edge_row"]) for row in rows}),
    }
    if not all(checks.values()):
        raise ValueError(
            f"name identity checks failed: {checks}; missing={len(missing_mib_ids)}"
        )
    output.mkdir(parents=True, exist_ok=True)
    rows_path = output / "matched_edges.jsonl"
    comparisons_path = output / "repeated_identifier_comparisons.jsonl"
    report_path = output / "report.json"
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    comparisons_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in comparisons),
        encoding="utf-8",
    )
    confidence = Counter(str(row["match_confidence"]) for row in rows)
    report = {
        "schema_version": 1,
        "status": "complete",
        "corridor_rows": len(rows),
        "confidence_counts": dict(sorted(confidence.items())),
        "rows_with_names": sum(bool(row["normalized_names"]) for row in rows),
        "rows_with_endpoint_class_codes": sum(
            bool(row["endpoint_class_codes"]) for row in rows
        ),
        "repeated_identifiers_in_corridor_sample": len(repeated),
        "repeated_identifier_pair_comparisons": len(comparisons),
        "name_relations": dict(sorted(name_relations.items())),
        "endpoint_class_relations": dict(sorted(class_relations.items())),
        "mib_edge_relations": dict(sorted(mib_edge_relations.items())),
        "name_relations_for_disjoint_mib_edge_sets": dict(
            sorted(independent_name_relations.items())
        ),
        "interpretation_boundary": (
            "High/medium corridor matches are correlation candidates, not proven object identity. "
            "Name agreement is not an independent name-key proof when both source rows share at "
            "least one selected MIB edge; it does support a cross-chunk local grouping signal."
        ),
        "checks": checks,
        "artifacts": {
            "matched_edges": rows_path.name,
            "repeated_identifier_comparisons": comparisons_path.name,
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(rows_path)}  {rows_path.name}\n"
        f"{sha256(comparisons_path)}  {comparisons_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    print(
        f"orion-mib-name-identity rows={len(rows)} repeated={len(repeated)} "
        f"comparisons={len(comparisons)} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identifiers", type=Path, required=True)
    parser.add_argument("--mib", type=Path, required=True)
    parser.add_argument("--corridor", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.identifiers, args.mib, args.corridor, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-name-identity error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
