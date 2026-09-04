#!/usr/bin/env python3
"""Validate Orion-to-MIB corridor candidates as connected topology chains."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict, deque
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import sys

from orion_mib_spatial_match import geometry_score, mib_points, original_points, read_jsonl


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-mib-chain stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def components(edge_ids: list[int], mib: dict[int, dict[str, object]]) -> list[set[int]]:
    by_node: dict[int, set[int]] = defaultdict(set)
    for edge_id in edge_ids:
        edge = mib[edge_id]
        by_node[int(edge["from_node_id"])].add(edge_id)
        by_node[int(edge["to_node_id"])].add(edge_id)
    unseen = set(edge_ids)
    result: list[set[int]] = []
    while unseen:
        first = next(iter(unseen))
        component: set[int] = set()
        queue = deque([first])
        while queue:
            edge_id = queue.popleft()
            if edge_id in component:
                continue
            component.add(edge_id)
            edge = mib[edge_id]
            for node in (int(edge["from_node_id"]), int(edge["to_node_id"])):
                queue.extend(by_node[node] - component)
        unseen -= component
        result.append(component)
    return result


def order_chain(
    edge_ids: set[int], mib: dict[int, dict[str, object]]
) -> tuple[list[int], list[tuple[float, float]]] | None:
    by_node: dict[int, list[int]] = defaultdict(list)
    for edge_id in edge_ids:
        edge = mib[edge_id]
        by_node[int(edge["from_node_id"])].append(edge_id)
        by_node[int(edge["to_node_id"])].append(edge_id)
    if any(len(values) > 2 for values in by_node.values()):
        return None
    endpoints = sorted(node for node, values in by_node.items() if len(values) == 1)
    if len(endpoints) != 2:
        return None
    current_node = endpoints[0]
    used: set[int] = set()
    ordered: list[int] = []
    points: list[tuple[float, float]] = []
    while len(used) < len(edge_ids):
        available = [edge_id for edge_id in by_node[current_node] if edge_id not in used]
        if len(available) != 1:
            return None
        edge_id = available[0]
        edge = mib[edge_id]
        geometry = mib_points(edge)
        if int(edge["from_node_id"]) == current_node:
            next_node = int(edge["to_node_id"])
        else:
            geometry.reverse()
            next_node = int(edge["from_node_id"])
        if points and points[-1] == geometry[0]:
            points.extend(geometry[1:])
        else:
            points.extend(geometry)
        used.add(edge_id)
        ordered.append(edge_id)
        current_node = next_node
    return ordered, points


def worker(
    job: tuple[list[dict[str, object]], dict[int, dict[str, object]], dict[tuple[int, int], dict[str, object]]]
) -> list[dict[str, object]]:
    rows, mib, originals = job
    output: list[dict[str, object]] = []
    for row in rows:
        key = (int(row["block_offset"]), int(row["edge_row"]))
        original = originals[key]
        candidates = row["matched_mib_edges"]
        if not candidates:
            output.append({**row, "chain": None, "chain_confidence": "none"})
            continue
        maximum_vote = max(int(item["sample_votes_within_20m"]) for item in candidates)
        minimum_vote = max(2, math.ceil(maximum_vote * 0.10))
        votes = {
            int(item["edge_id"]): int(item["sample_votes_within_20m"])
            for item in candidates
            if int(item["sample_votes_within_20m"]) >= minimum_vote
        }
        if not votes:
            output.append({**row, "chain": None, "chain_confidence": "none"})
            continue
        found = components(list(votes), mib)
        found.sort(key=lambda group: sum(votes[edge_id] for edge_id in group), reverse=True)
        best = found[0]
        selected_votes = sum(votes[edge_id] for edge_id in best)
        vote_share = selected_votes / sum(votes.values())
        ordered = order_chain(best, mib)
        chain: dict[str, object] | None = None
        confidence = "none"
        if ordered is not None:
            ordered_ids, points = ordered
            metrics = geometry_score(original_points(original), points)
            if (
                vote_share >= 0.90
                and float(metrics["endpoint_error_metres"]) <= 20
                and float(metrics["hausdorff_metres"]) <= 25
                and float(metrics["mean_shape_error_metres"]) <= 8
                and float(metrics["length_ratio"]) <= 1.20
            ):
                confidence = "high"
            elif (
                vote_share >= 0.75
                and float(metrics["endpoint_error_metres"]) <= 45
                and float(metrics["hausdorff_metres"]) <= 50
                and float(metrics["mean_shape_error_metres"]) <= 18
                and float(metrics["length_ratio"]) <= 1.40
            ):
                confidence = "medium"
            else:
                confidence = "low"
            chain = {
                "edge_ids": ordered_ids,
                "edge_id_hex": [f"0x{edge_id:08x}" for edge_id in ordered_ids],
                "edge_count": len(ordered_ids),
                "vote_share": vote_share,
                "filtered_candidate_count": len(votes),
                "component_count": len(found),
                **metrics,
            }
        else:
            chain = {
                "edge_ids": sorted(best),
                "edge_id_hex": [f"0x{edge_id:08x}" for edge_id in sorted(best)],
                "edge_count": len(best),
                "vote_share": vote_share,
                "filtered_candidate_count": len(votes),
                "component_count": len(found),
                "rejection": "largest component is branched, cyclic, or incomplete",
            }
        output.append({**row, "chain": chain, "chain_confidence": confidence})
    return output


def run(
    corridor_path: Path,
    original_path: Path,
    mib_path: Path,
    output: Path,
    jobs: int,
) -> dict[str, object]:
    corridor = read_jsonl(corridor_path)
    selected = [row for row in corridor if row["match_confidence"] in {"high", "medium"}]
    originals = {
        (int(row["block_offset"]), int(row["edge_row"])): row
        for row in read_jsonl(original_path)
    }
    mib = {int(row["edge_id"]): row for row in read_jsonl(mib_path)}
    work = [(selected[index::jobs], mib, originals) for index in range(jobs) if selected[index::jobs]]
    progress("start", corridor=len(corridor), selected=len(selected), jobs=len(work))
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        chunks = list(pool.map(worker, work))
    rows = [row for chunk in chunks for row in chunk]
    rows.sort(key=lambda row: (int(row["block_offset"]), int(row["edge_row"])))
    confidence = Counter(str(row["chain_confidence"]) for row in rows)
    chain_lengths = Counter(
        int(row["chain"]["edge_count"])
        for row in rows
        if row["chain_confidence"] in {"high", "medium"}
    )
    checks = {
        "selected_rows_preserved": len(rows) == len(selected),
        "selected_keys_unique": len(rows)
        == len({(row["block_offset"], row["edge_row"]) for row in rows}),
    }
    if not all(checks.values()):
        raise ValueError(f"chain checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    rows_path = output / "chains.jsonl"
    report_path = output / "report.json"
    rows_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    report = {
        "schema_version": 1,
        "status": "topology_chain_candidate_complete",
        "corridor_input": str(corridor_path),
        "original_input": str(original_path),
        "mib_input": str(mib_path),
        "jobs": jobs,
        "corridor_rows": len(corridor),
        "selected_high_medium_corridors": len(selected),
        "chain_confidence_counts": dict(sorted(confidence.items())),
        "accepted_chain_edge_count_distribution": {
            str(key): value for key, value in sorted(chain_lengths.items())
        },
        "checks": checks,
        "thresholds": {
            "high": "vote_share>=90%, endpoint<=20m, hausdorff<=25m, mean<=8m, length_ratio<=1.20",
            "medium": "vote_share>=75%, endpoint<=45m, hausdorff<=50m, mean<=18m, length_ratio<=1.40",
        },
        "interpretation_boundary": "Accepted chains remain cross-version candidates until stable attributes also agree.",
        "artifacts": {"chains": rows_path.name},
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(rows_path)}  {rows_path.name}\n{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    progress("complete", **dict(sorted(confidence.items())))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corridor", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("mib", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    try:
        report = run(args.corridor, args.original, args.mib, args.output, args.jobs)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-chain error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
