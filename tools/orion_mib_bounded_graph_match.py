#!/usr/bin/env python3
"""Find bounded MIB graph paths along an original Orion edge corridor."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
import hashlib
import heapq
import json
import math
from pathlib import Path
import sys

from orion_mib_spatial_match import (
    bbox,
    directed_distances,
    geometry_score,
    length,
    mib_points,
    original_points,
    project,
    read_jsonl,
    resample,
)


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-mib-graph-search stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def path_geometry(
    path: tuple[tuple[int, int], ...], mib: dict[int, dict[str, object]]
) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    for edge_id, from_node in path:
        edge = mib[edge_id]
        geometry = mib_points(edge)
        if int(edge["from_node_id"]) != from_node:
            geometry.reverse()
        if points and points[-1] == geometry[0]:
            points.extend(geometry[1:])
        else:
            points.extend(geometry)
    return points


def worker(
    job: tuple[
        list[dict[str, object]],
        dict[tuple[int, int], dict[str, object]],
        list[dict[str, object]],
        float,
        int,
    ]
) -> list[dict[str, object]]:
    corridor_rows, originals, candidates, corridor_metres, max_hops = job
    mib = {int(row["edge_id"]): row for row in candidates}
    pad = corridor_metres / 80_000
    cell_size = max(pad, 0.002)
    grid: dict[tuple[int, int], list[int]] = defaultdict(list)
    for index, candidate in enumerate(candidates):
        bounds = candidate["bbox"]
        for x in range(math.floor(bounds[0] / cell_size), math.floor(bounds[2] / cell_size) + 1):
            for y in range(math.floor(bounds[1] / cell_size), math.floor(bounds[3] / cell_size) + 1):
                grid[(x, y)].append(index)

    output: list[dict[str, object]] = []
    for corridor_row in corridor_rows:
        key = (int(corridor_row["block_offset"]), int(corridor_row["edge_row"]))
        original_row = originals[key]
        raw_original = original_points(original_row)
        latitude_origin = sum(point[1] for point in raw_original) / len(raw_original)
        original_xy = project(raw_original, latitude_origin)
        original_segments = original_xy
        original_length = length(original_xy)
        bounds = bbox(raw_original)
        indexes = {
            index
            for x in range(math.floor((bounds[0] - pad) / cell_size), math.floor((bounds[2] + pad) / cell_size) + 1)
            for y in range(math.floor((bounds[1] - pad) / cell_size), math.floor((bounds[3] + pad) / cell_size) + 1)
            for index in grid.get((x, y), [])
        }

        adjacency: dict[int, list[tuple[int, int, float, float]]] = defaultdict(list)
        node_positions: dict[int, tuple[float, float]] = {}
        eligible_ids: set[int] = set()
        for index in indexes:
            edge = candidates[index]
            edge_id = int(edge["edge_id"])
            raw_geometry = mib_points(edge)
            geometry = project(raw_geometry, latitude_origin)
            distances = directed_distances(resample(geometry, spacing=12), original_segments)
            mean_distance = sum(distances) / len(distances)
            maximum_distance = max(distances)
            if mean_distance > corridor_metres * 0.55 or maximum_distance > corridor_metres:
                continue
            edge_length = length(geometry)
            left = int(edge["from_node_id"])
            right = int(edge["to_node_id"])
            node_positions.setdefault(left, geometry[0])
            node_positions.setdefault(right, geometry[-1])
            cost = edge_length + mean_distance * 4
            adjacency[left].append((right, edge_id, edge_length, cost))
            adjacency[right].append((left, edge_id, edge_length, cost))
            eligible_ids.add(edge_id)

        if not adjacency:
            output.append({**corridor_row, "graph_match": None, "graph_confidence": "none"})
            continue
        start_point, end_point = original_xy[0], original_xy[-1]
        start_nodes = sorted(
            ((math.dist(position, start_point), node) for node, position in node_positions.items()),
        )[:6]
        end_nodes = sorted(
            ((math.dist(position, end_point), node) for node, position in node_positions.items()),
        )[:6]
        start_nodes = [(distance, node) for distance, node in start_nodes if distance <= corridor_metres]
        end_set = {node for distance, node in end_nodes if distance <= corridor_metres}
        if not start_nodes or not end_set:
            output.append({**corridor_row, "graph_match": None, "graph_confidence": "none"})
            continue

        maximum_length = max(original_length * 1.65, original_length + 120)
        heap: list[tuple[float, int, int, float, tuple[tuple[int, int], ...], frozenset[int]]] = []
        for endpoint_distance, node in start_nodes:
            heapq.heappush(heap, (endpoint_distance * 3, 0, node, 0.0, (), frozenset()))
        best_state: dict[tuple[int, int], float] = {}
        completed: list[tuple[dict[str, float | str], tuple[tuple[int, int], ...]]] = []
        while heap and len(completed) < 12:
            cost, hops, node, travelled, path, used = heapq.heappop(heap)
            state = (node, hops)
            if cost > best_state.get(state, float("inf")):
                continue
            best_state[state] = cost
            if node in end_set and path:
                geometry = path_geometry(path, mib)
                completed.append((geometry_score(raw_original, geometry), path))
                continue
            if hops >= max_hops:
                continue
            for next_node, edge_id, edge_length, edge_cost in adjacency[node]:
                if edge_id in used or travelled + edge_length > maximum_length:
                    continue
                next_cost = cost + edge_cost
                next_state = (next_node, hops + 1)
                if next_cost >= best_state.get(next_state, float("inf")):
                    continue
                heapq.heappush(
                    heap,
                    (
                        next_cost,
                        hops + 1,
                        next_node,
                        travelled + edge_length,
                        path + ((edge_id, node),),
                        used | {edge_id},
                    ),
                )
        if not completed:
            output.append({**corridor_row, "graph_match": None, "graph_confidence": "none"})
            continue
        completed.sort(key=lambda item: float(item[0]["score"]))
        metrics, best_path = completed[0]
        confidence = "low"
        if (
            float(metrics["endpoint_error_metres"]) <= 15
            and float(metrics["hausdorff_metres"]) <= 20
            and float(metrics["mean_shape_error_metres"]) <= 7
            and float(metrics["length_ratio"]) <= 1.18
        ):
            confidence = "high"
        elif (
            float(metrics["endpoint_error_metres"]) <= 35
            and float(metrics["hausdorff_metres"]) <= 45
            and float(metrics["mean_shape_error_metres"]) <= 15
            and float(metrics["length_ratio"]) <= 1.35
        ):
            confidence = "medium"
        path_ids = [edge_id for edge_id, _ in best_path]
        urban_values = {int(bool(mib[edge_id]["urban"])) for edge_id in path_ids}
        bit6_values = {
            int(any(int(flag) & 0x40 for flag in mib[edge_id]["geometry_part_secondary_flags"]))
            for edge_id in path_ids
        }
        output.append(
            {
                **corridor_row,
                "graph_confidence": confidence,
                "graph_match": {
                    "edge_ids": path_ids,
                    "edge_id_hex": [f"0x{edge_id:08x}" for edge_id in path_ids],
                    "edge_count": len(path_ids),
                    "eligible_corridor_edges": len(eligible_ids),
                    "mib_urban_consensus": next(iter(urban_values)) if len(urban_values) == 1 else None,
                    "mib_secondary_bit6_consensus": next(iter(bit6_values)) if len(bit6_values) == 1 else None,
                    **metrics,
                },
            }
        )
    return output


def run(corridor_path: Path, original_path: Path, mib_path: Path, output: Path, jobs: int, corridor_metres: float, max_hops: int) -> dict[str, object]:
    corridor = read_jsonl(corridor_path)
    selected = [row for row in corridor if row["match_confidence"] in {"high", "medium"}]
    originals = {(int(row["block_offset"]), int(row["edge_row"])): row for row in read_jsonl(original_path)}
    candidates = read_jsonl(mib_path)
    work = [(selected[index::jobs], originals, candidates, corridor_metres, max_hops) for index in range(jobs) if selected[index::jobs]]
    progress("start", selected=len(selected), candidates=len(candidates), jobs=len(work))
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        chunks = list(pool.map(worker, work))
    rows = [row for chunk in chunks for row in chunk]
    rows.sort(key=lambda row: (int(row["block_offset"]), int(row["edge_row"])))
    confidence = Counter(str(row["graph_confidence"]) for row in rows)
    path_lengths = Counter(int(row["graph_match"]["edge_count"]) for row in rows if row["graph_confidence"] in {"high", "medium"})
    checks = {"selected_rows_preserved": len(rows) == len(selected), "keys_unique": len(rows) == len({(row["block_offset"], row["edge_row"]) for row in rows})}
    if not all(checks.values()):
        raise ValueError(f"bounded graph checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    rows_path = output / "matches.jsonl"
    report_path = output / "report.json"
    rows_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    report = {
        "schema_version": 1,
        "status": "bounded_graph_candidate_complete",
        "selected_corridor_rows": len(selected),
        "jobs": jobs,
        "corridor_metres": corridor_metres,
        "max_hops": max_hops,
        "confidence_counts": dict(sorted(confidence.items())),
        "accepted_path_edge_count_distribution": {str(key): value for key, value in sorted(path_lengths.items())},
        "checks": checks,
        "interpretation_boundary": "Graph paths are geometry/topology candidates; stable attribute agreement is still required.",
        "artifacts": {"matches": rows_path.name},
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(f"{sha256(rows_path)}  {rows_path.name}\n{sha256(report_path)}  {report_path.name}\n", encoding="ascii")
    progress("complete", **dict(sorted(confidence.items())))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corridor", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument("mib", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--corridor-metres", type=float, default=80.0)
    parser.add_argument("--max-hops", type=int, default=12)
    args = parser.parse_args()
    try:
        report = run(args.corridor, args.original, args.mib, args.output, args.jobs, args.corridor_metres, args.max_hops)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-graph-search error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
