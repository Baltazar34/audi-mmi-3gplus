#!/usr/bin/env python3
"""Match Orion edges to one or more MIB segments by corridor coverage."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import sys

from orion_mib_spatial_match import (
    bbox,
    mib_points,
    original_points,
    point_segment_distance,
    project,
    read_jsonl,
    resample,
)


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-mib-corridor stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def worker(
    job: tuple[list[dict[str, object]], list[dict[str, object]], float]
) -> list[dict[str, object]]:
    originals, candidates, radius_metres = job
    pad = radius_metres / 80_000
    cell_size = max(pad, 0.002)
    by_id = {int(candidate["edge_id"]): candidate for candidate in candidates}
    grid: dict[tuple[int, int], list[int]] = {}
    for index, candidate in enumerate(candidates):
        bounds = candidate["bbox"]
        for x in range(
            math.floor(float(bounds[0]) / cell_size),
            math.floor(float(bounds[2]) / cell_size) + 1,
        ):
            for y in range(
                math.floor(float(bounds[1]) / cell_size),
                math.floor(float(bounds[3]) / cell_size) + 1,
            ):
                grid.setdefault((x, y), []).append(index)

    output: list[dict[str, object]] = []
    for row in originals:
        raw_points = original_points(row)
        bounds = bbox(raw_points)
        indexes = {
            index
            for x in range(
                math.floor((bounds[0] - pad) / cell_size),
                math.floor((bounds[2] + pad) / cell_size) + 1,
            )
            for y in range(
                math.floor((bounds[1] - pad) / cell_size),
                math.floor((bounds[3] + pad) / cell_size) + 1,
            )
            for index in grid.get((x, y), [])
        }
        latitude_origin = sum(point[1] for point in raw_points) / len(raw_points)
        sampled = resample(project(raw_points, latitude_origin), spacing=8.0)
        projected_candidates: list[
            tuple[dict[str, object], list[tuple[tuple[float, float], tuple[float, float]]]]
        ] = []
        for index in indexes:
            candidate = candidates[index]
            points = project(mib_points(candidate), latitude_origin)
            projected_candidates.append((candidate, list(zip(points, points[1:]))))
        nearest: list[tuple[float, dict[str, object]]] = []
        for point in sampled:
            best: tuple[float, dict[str, object]] | None = None
            for candidate, segments in projected_candidates:
                distance = min(
                    point_segment_distance(point, left, right)
                    for left, right in segments
                )
                if best is None or distance < best[0]:
                    best = (distance, candidate)
            if best is not None:
                nearest.append(best)
        distances = [item[0] for item in nearest]
        within_10 = sum(value <= 10 for value in distances) / len(sampled) if sampled else 0
        within_20 = sum(value <= 20 for value in distances) / len(sampled) if sampled else 0
        mean = sum(distances) / len(distances) if len(distances) == len(sampled) else None
        maximum = max(distances) if len(distances) == len(sampled) else None
        confidence = "none"
        if mean is not None:
            if within_10 >= 0.95 and mean <= 5 and maximum <= 20:
                confidence = "high"
            elif within_20 >= 0.90 and mean <= 12 and maximum <= 45:
                confidence = "medium"
            else:
                confidence = "low"
        votes = Counter(
            int(candidate["edge_id"])
            for distance, candidate in nearest
            if distance <= 20
        )
        selected_ids = [edge_id for edge_id, _ in votes.most_common()]
        selected = [by_id[edge_id] for edge_id in selected_ids]
        urban_values = {int(bool(candidate["urban"])) for candidate in selected}
        bit6_values = {
            int(
                any(
                    int(value) & 0x40
                    for value in candidate["geometry_part_secondary_flags"]
                )
            )
            for candidate in selected
        }
        output.append(
            {
                "block_offset": row["block_offset"],
                "block_offset_hex": row["block_offset_hex"],
                "edge_row": row["edge_row"],
                "original_properties": row["properties"],
                "match_confidence": confidence,
                "sample_count": len(sampled),
                "candidate_count": len(indexes),
                "coverage_within_10m": within_10,
                "coverage_within_20m": within_20,
                "mean_distance_metres": mean,
                "maximum_distance_metres": maximum,
                "matched_mib_edges": [
                    {
                        "edge_id": candidate["edge_id"],
                        "edge_id_hex": candidate["edge_id_hex"],
                        "sample_votes_within_20m": votes[int(candidate["edge_id"])],
                        "urban": candidate["urban"],
                        "secondary_bit6": any(
                            int(value) & 0x40
                            for value in candidate["geometry_part_secondary_flags"]
                        ),
                    }
                    for candidate in selected
                ],
                "mib_urban_consensus": (
                    next(iter(urban_values)) if len(urban_values) == 1 else None
                ),
                "mib_secondary_bit6_consensus": (
                    next(iter(bit6_values)) if len(bit6_values) == 1 else None
                ),
            }
        )
    return output


def run(
    original_path: Path,
    mib_path: Path,
    output: Path,
    jobs: int,
    radius_metres: float,
) -> dict[str, object]:
    originals = read_jsonl(original_path)
    candidates = read_jsonl(mib_path)
    work = [
        (originals[index::jobs], candidates, radius_metres)
        for index in range(jobs)
        if originals[index::jobs]
    ]
    progress("start", originals=len(originals), candidates=len(candidates), jobs=len(work))
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        chunks = list(pool.map(worker, work))
    rows = [row for chunk in chunks for row in chunk]
    rows.sort(key=lambda row: (int(row["block_offset"]), int(row["edge_row"])))
    confidence = Counter(str(row["match_confidence"]) for row in rows)
    comparisons: Counter[str] = Counter()
    bit6: Counter[str] = Counter()
    comparisons_by_confidence: dict[str, Counter[str]] = {
        "high": Counter(),
        "medium": Counter(),
    }
    bit6_by_confidence: dict[str, Counter[str]] = {
        "high": Counter(),
        "medium": Counter(),
    }
    for row in rows:
        if row["match_confidence"] not in {"high", "medium"}:
            continue
        baseline = row["original_properties"]["effective_baseline_tuple_or"]
        if row["mib_urban_consensus"] is not None:
            key = f"{baseline[1]} -> {row['mib_urban_consensus']}"
            comparisons[key] += 1
            comparisons_by_confidence[str(row["match_confidence"])][key] += 1
        if row["mib_secondary_bit6_consensus"] is not None:
            key = f"{baseline[2]} -> {row['mib_secondary_bit6_consensus']}"
            bit6[key] += 1
            bit6_by_confidence[str(row["match_confidence"])][key] += 1
    checks = {
        "all_original_edges_scored": len(rows) == len(originals),
        "keys_unique": len(rows)
        == len({(row["block_offset"], row["edge_row"]) for row in rows}),
        "coverage_fractions_in_range": all(
            0 <= float(row["coverage_within_10m"]) <= 1
            and 0 <= float(row["coverage_within_20m"]) <= 1
            for row in rows
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"corridor checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    matches_path = output / "matches.jsonl"
    report_path = output / "report.json"
    matches_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "corridor_candidate_match_complete",
        "original_input": str(original_path),
        "mib_input": str(mib_path),
        "jobs": jobs,
        "radius_metres": radius_metres,
        "original_edges": len(rows),
        "mib_candidates": len(candidates),
        "confidence_counts": dict(sorted(confidence.items())),
        "urban_original_to_mib_consensus": dict(sorted(comparisons.items())),
        "audiurban_to_mib_secondary_bit6_consensus": dict(sorted(bit6.items())),
        "correlations_by_confidence": {
            confidence_name: {
                "urban_original_to_mib_consensus": dict(
                    sorted(comparisons_by_confidence[confidence_name].items())
                ),
                "audiurban_to_mib_secondary_bit6_consensus": dict(
                    sorted(bit6_by_confidence[confidence_name].items())
                ),
            }
            for confidence_name in ("high", "medium")
        },
        "checks": checks,
        "thresholds": {
            "high": "coverage10>=95%, mean<=5m, max<=20m",
            "medium": "coverage20>=90%, mean<=12m, max<=45m",
        },
        "interpretation_boundary": (
            "One-to-many corridor candidates are suitable for correlation only. "
            "They are not yet a proven object identity mapping."
        ),
        "artifacts": {"matches": matches_path.name},
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_path = output / "CHECKSUMS.sha256"
    checksum_path.write_text(
        f"{sha256(matches_path)}  {matches_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    progress("complete", **dict(sorted(confidence.items())))
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("mib", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--radius-metres", type=float, default=80.0)
    args = parser.parse_args()
    try:
        report = run(args.original, args.mib, args.output, args.jobs, args.radius_metres)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-corridor error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
