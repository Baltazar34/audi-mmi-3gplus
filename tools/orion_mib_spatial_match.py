#!/usr/bin/env python3
"""Spatially match decoded original Orion edges to compact MIB candidates."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
import math
from pathlib import Path
import sys


EARTH_METRES = 6_371_008.8


def progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-mib-match stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source]


def original_points(row: dict[str, object]) -> list[tuple[float, float]]:
    result: list[tuple[float, float]] = []
    for part in row["centerline_geometry"]["parts"]:
        points = [
            (float(point["longitude"]), float(point["latitude"]))
            for point in part["positions"]
        ]
        if result and points and result[-1] == points[0]:
            result.extend(points[1:])
        else:
            result.extend(points)
    return result


def mib_points(row: dict[str, object]) -> list[tuple[float, float]]:
    return [
        (float(point["longitude"]), float(point["latitude"]))
        for point in row["centerline"]
    ]


def project(
    points: list[tuple[float, float]], latitude_origin: float
) -> list[tuple[float, float]]:
    scale_x = math.pi / 180 * EARTH_METRES * math.cos(math.radians(latitude_origin))
    scale_y = math.pi / 180 * EARTH_METRES
    return [(lon * scale_x, lat * scale_y) for lon, lat in points]


def length(points: list[tuple[float, float]]) -> float:
    return sum(
        math.hypot(right[0] - left[0], right[1] - left[1])
        for left, right in zip(points, points[1:])
    )


def resample(
    points: list[tuple[float, float]], spacing: float = 8.0
) -> list[tuple[float, float]]:
    if len(points) < 2:
        return points
    output = [points[0]]
    for left, right in zip(points, points[1:]):
        segment = math.hypot(right[0] - left[0], right[1] - left[1])
        divisions = max(1, math.ceil(segment / spacing))
        output.extend(
            (
                left[0] + (right[0] - left[0]) * index / divisions,
                left[1] + (right[1] - left[1]) * index / divisions,
            )
            for index in range(1, divisions + 1)
        )
    if len(output) > 512:
        step = (len(output) - 1) / 511
        output = [output[round(index * step)] for index in range(512)]
    return output


def point_segment_distance(
    point: tuple[float, float],
    left: tuple[float, float],
    right: tuple[float, float],
) -> float:
    dx = right[0] - left[0]
    dy = right[1] - left[1]
    denominator = dx * dx + dy * dy
    if denominator == 0:
        return math.hypot(point[0] - left[0], point[1] - left[1])
    ratio = max(
        0.0,
        min(1.0, ((point[0] - left[0]) * dx + (point[1] - left[1]) * dy) / denominator),
    )
    return math.hypot(
        point[0] - (left[0] + ratio * dx),
        point[1] - (left[1] + ratio * dy),
    )


def directed_distances(
    sampled: list[tuple[float, float]], target: list[tuple[float, float]]
) -> list[float]:
    segments = list(zip(target, target[1:]))
    return [
        min(point_segment_distance(point, left, right) for left, right in segments)
        for point in sampled
    ]


def geometry_score(
    original: list[tuple[float, float]], candidate: list[tuple[float, float]]
) -> dict[str, float | str]:
    latitude_origin = sum(point[1] for point in original) / len(original)
    left = project(original, latitude_origin)
    right = project(candidate, latitude_origin)
    left_length = length(left)
    right_length = length(right)
    forward_endpoint = max(
        math.dist(left[0], right[0]), math.dist(left[-1], right[-1])
    )
    reverse_endpoint = max(
        math.dist(left[0], right[-1]), math.dist(left[-1], right[0])
    )
    orientation = "forward" if forward_endpoint <= reverse_endpoint else "reverse"
    endpoint_error = min(forward_endpoint, reverse_endpoint)
    left_distances = directed_distances(resample(left), right)
    right_distances = directed_distances(resample(right), left)
    all_distances = left_distances + right_distances
    mean_error = sum(all_distances) / len(all_distances)
    hausdorff = max(all_distances)
    length_ratio = max(left_length, right_length) / max(1.0, min(left_length, right_length))
    score = endpoint_error + mean_error * 2 + hausdorff * 0.5 + (length_ratio - 1) * 40
    return {
        "score": score,
        "orientation": orientation,
        "endpoint_error_metres": endpoint_error,
        "mean_shape_error_metres": mean_error,
        "hausdorff_metres": hausdorff,
        "original_length_metres": left_length,
        "mib_length_metres": right_length,
        "length_ratio": length_ratio,
    }


def bbox(points: list[tuple[float, float]]) -> tuple[float, float, float, float]:
    return (
        min(point[0] for point in points),
        min(point[1] for point in points),
        max(point[0] for point in points),
        max(point[1] for point in points),
    )


def expanded_intersects(
    left: tuple[float, float, float, float],
    right: list[float],
    pad_degrees: float,
) -> bool:
    return not (
        right[2] < left[0] - pad_degrees
        or right[0] > left[2] + pad_degrees
        or right[3] < left[1] - pad_degrees
        or right[1] > left[3] + pad_degrees
    )


def worker(
    job: tuple[list[dict[str, object]], list[dict[str, object]], float]
) -> list[dict[str, object]]:
    originals, candidates, search_radius_metres = job
    pad = search_radius_metres / 80_000
    candidate_points = [(row, mib_points(row)) for row in candidates]
    cell_size = max(pad, 0.002)
    grid: dict[tuple[int, int], list[int]] = {}
    for index, (candidate, _) in enumerate(candidate_points):
        bounds = candidate["bbox"]
        min_x = math.floor(float(bounds[0]) / cell_size)
        max_x = math.floor(float(bounds[2]) / cell_size)
        min_y = math.floor(float(bounds[1]) / cell_size)
        max_y = math.floor(float(bounds[3]) / cell_size)
        for x in range(min_x, max_x + 1):
            for y in range(min_y, max_y + 1):
                grid.setdefault((x, y), []).append(index)
    output: list[dict[str, object]] = []
    for row in originals:
        points = original_points(row)
        bounds = bbox(points)
        min_x = math.floor((bounds[0] - pad) / cell_size)
        max_x = math.floor((bounds[2] + pad) / cell_size)
        min_y = math.floor((bounds[1] - pad) / cell_size)
        max_y = math.floor((bounds[3] + pad) / cell_size)
        candidate_indexes = {
            index
            for x in range(min_x, max_x + 1)
            for y in range(min_y, max_y + 1)
            for index in grid.get((x, y), [])
        }
        shortlist = [
            candidate_points[index]
            for index in candidate_indexes
            for candidate, candidate_geometry in [candidate_points[index]]
            if expanded_intersects(bounds, candidate["bbox"], pad)
        ]
        scores = [
            (geometry_score(points, candidate_geometry), candidate)
            for candidate, candidate_geometry in shortlist
        ]
        scores.sort(key=lambda item: float(item[0]["score"]))
        ranked = scores[:2]
        best = ranked[0] if ranked else None
        second_score = float(ranked[1][0]["score"]) if len(ranked) > 1 else None
        match: dict[str, object] | None = None
        confidence = "none"
        if best is not None:
            metrics, candidate = best
            endpoint_error = float(metrics["endpoint_error_metres"])
            shape_error = float(metrics["hausdorff_metres"])
            mean_error = float(metrics["mean_shape_error_metres"])
            length_ratio = float(metrics["length_ratio"])
            margin = (
                second_score - float(metrics["score"])
                if second_score is not None
                else None
            )
            if endpoint_error <= 12 and shape_error <= 15 and mean_error <= 6 and length_ratio <= 1.15:
                confidence = "high"
            elif endpoint_error <= 30 and shape_error <= 40 and mean_error <= 15 and length_ratio <= 1.35:
                confidence = "medium"
            else:
                confidence = "low"
            match = {
                "mib_edge_id": candidate["edge_id"],
                "mib_edge_id_hex": candidate["edge_id_hex"],
                "mib_urban": candidate["urban"],
                "mib_geometry_part_secondary_flags": candidate[
                    "geometry_part_secondary_flags"
                ],
                **metrics,
                "second_candidate_score": second_score,
                "score_margin": margin,
            }
        output.append(
            {
                "block_offset": row["block_offset"],
                "block_offset_hex": row["block_offset_hex"],
                "edge_row": row["edge_row"],
                "original_properties": row["properties"],
                "match_confidence": confidence,
                "candidate_count": len(shortlist),
                "match": match,
            }
        )
    return output


def run(
    original_path: Path,
    mib_path: Path,
    output: Path,
    jobs: int,
    search_radius_metres: float,
) -> dict[str, object]:
    originals = read_jsonl(original_path)
    candidates = read_jsonl(mib_path)
    assignments = [originals[index::jobs] for index in range(jobs)]
    work = [
        (assignment, candidates, search_radius_metres)
        for assignment in assignments
        if assignment
    ]
    progress(
        "start", originals=len(originals), candidates=len(candidates), jobs=len(work)
    )
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        chunks = list(pool.map(worker, work))
    rows = [row for chunk in chunks for row in chunk]
    rows.sort(key=lambda row: (int(row["block_offset"]), int(row["edge_row"])))
    confidence = Counter(str(row["match_confidence"]) for row in rows)
    high_mib_ids = [
        int(row["match"]["mib_edge_id"])
        for row in rows
        if row["match_confidence"] == "high"
    ]
    high_unique = set(high_mib_ids)
    high_rows = [row for row in rows if row["match_confidence"] == "high"]
    tuple_vs_mib_urban: Counter[str] = Counter()
    audiurban_vs_bit6: Counter[str] = Counter()
    for row in high_rows:
        baseline = row["original_properties"]["effective_baseline_tuple_or"]
        mib_urban = int(bool(row["match"]["mib_urban"]))
        tuple_vs_mib_urban[
            "+".join(map(str, baseline)) + f" -> {mib_urban}"
        ] += 1
        bit6 = int(
            any(
                int(value) & 0x40
                for value in row["match"]["mib_geometry_part_secondary_flags"]
            )
        )
        audiurban_vs_bit6[f"{int(baseline[2])} -> {bit6}"] += 1
    checks = {
        "all_original_edges_scored": len(rows) == len(originals),
        "original_keys_unique": len(rows)
        == len({(row["block_offset"], row["edge_row"]) for row in rows}),
        "all_high_matches_have_mib_candidate": all(row["match"] for row in high_rows),
    }
    if not all(checks.values()):
        raise ValueError(f"spatial match checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    matches_path = output / "matches.jsonl"
    report_path = output / "report.json"
    matches_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )
    report = {
        "schema_version": 1,
        "status": "candidate_match_complete",
        "original_input": str(original_path),
        "mib_input": str(mib_path),
        "jobs": jobs,
        "search_radius_metres": search_radius_metres,
        "original_edges": len(originals),
        "mib_candidates": len(candidates),
        "confidence_counts": dict(sorted(confidence.items())),
        "high_confidence_unique_mib_edges": len(high_unique),
        "high_confidence_duplicate_assignments": len(high_mib_ids) - len(high_unique),
        "high_confidence_property_tuple_vs_mib_urban": dict(
            sorted(tuple_vs_mib_urban.items())
        ),
        "high_confidence_audiurban_vs_mib_secondary_bit6": dict(
            sorted(audiurban_vs_bit6.items())
        ),
        "thresholds": {
            "high": "endpoint<=12m, hausdorff<=15m, mean<=6m, length_ratio<=1.15",
            "medium": "endpoint<=30m, hausdorff<=40m, mean<=15m, length_ratio<=1.35",
        },
        "checks": checks,
        "artifacts": {"matches": matches_path.name},
        "interpretation_boundary": (
            "Candidate geometry matches are evidence for analysis, not yet a "
            "proven one-to-one cross-version identity mapping. Duplicate MIB "
            "assignments and score margins must be resolved before deriving AudiUrban."
        ),
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
    progress("complete", high=confidence["high"], medium=confidence["medium"], low=confidence["low"], none=confidence["none"])
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("mib", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--search-radius-metres", type=float, default=150.0)
    args = parser.parse_args()
    try:
        report = run(
            args.original,
            args.mib,
            args.output,
            args.jobs,
            args.search_radius_metres,
        )
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-mib-match error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
