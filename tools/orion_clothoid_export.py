#!/usr/bin/env python3
"""Validate and export the pre-writer Orion clothoid source layer."""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path
import sys

from basic_geometry_decode import _build_cluster, _group_entries, decode_geometry_record
from orion_clothoid import piecewise_linear_clothoids
from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 1


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"orion-clothoid-export stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _centerline(parts: tuple[object, ...]) -> list[object]:
    points: list[object] = []
    for part in parts:
        part_points = part.points
        if points and points[-1] == part_points[0]:
            points.extend(part_points[1:])
        else:
            points.extend(part_points)
    return points


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    source_path = output / "clothoid_edges.jsonl"
    temporary = source_path.with_suffix(".jsonl.tmp")
    counts: collections.Counter[str] = collections.Counter()
    maximum_endpoint_error = 0.0
    emitted = 0

    _progress("validate", clusters=len(order))
    with psf.open("rb") as source, temporary.open("w", encoding="utf-8") as target:
        for ordinal, cluster_id in enumerate(order, start=1):
            handles = grouped[cluster_id]
            topology = _decode_indexed_lzma(source, handles[0])
            geometry_payload = _decode_indexed_lzma(source, handles[1])
            cluster = _build_cluster(cluster_id, topology, geometry_payload)
            for edge_index in range(cluster.edge_count):
                parts = decode_geometry_record(cluster, edge_index)
                points = _centerline(parts)
                segments = piecewise_linear_clothoids(points)
                counts["edges"] += 1
                counts["source_points"] += len(points)
                counts["segments"] += len(segments)
                counts["zero_length_source_legs"] += max(0, len(points) - 1 - len(segments))
                for segment in segments:
                    end_x, end_y = segment.endpoint()
                    error = math.hypot(end_x - segment.end.x, end_y - segment.end.y)
                    maximum_endpoint_error = max(maximum_endpoint_error, error)
                if sample_limit == 0 or emitted < sample_limit:
                    target.write(
                        json.dumps(
                            {
                                "schema_version": SCHEMA_VERSION,
                                "record_type": "orion-clothoid-centerline-source",
                                "conversion": "lossless-piecewise-linear-zero-curvature",
                                "tangent_continuity_at_source_corners": False,
                                "cluster_id": cluster_id,
                                "edge_index": edge_index,
                                "edge_id": (cluster_id << 8) | edge_index,
                                "edge_id_hex": f"0x{((cluster_id << 8) | edge_index):08x}",
                                "segments": [
                                    {
                                        "index": segment.index,
                                        "start_mercator": segment.start.as_list(),
                                        "end_mercator": segment.end.as_list(),
                                        "heading_radians": segment.heading_radians,
                                        "length_mercator": segment.length,
                                        "start_curvature": segment.start_curvature,
                                        "curvature_rate": segment.curvature_rate,
                                    }
                                    for segment in segments
                                ],
                            },
                            sort_keys=True,
                        )
                        + "\n"
                    )
                    emitted += 1
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress(
                    "validate-progress",
                    clusters=ordinal,
                    total=len(order),
                    edges=counts["edges"],
                    segments=counts["segments"],
                )
    temporary.replace(source_path)

    checks = {
        "all_edges_have_source_geometry": counts["edges"] > 0,
        "every_nonzero_source_leg_has_one_segment": counts["segments"]
        + counts["zero_length_source_legs"]
        == counts["source_points"] - counts["edges"],
        "segment_endpoints_roundtrip": maximum_endpoint_error < 1e-8,
    }
    report = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete" if all(checks.values()) else "failed",
        "source": {"path": str(psf), "sha256": _sha256(psf)},
        "conversion": {
            "model": "ClothoidCenterlineGeometry source",
            "method": "one kappa=0/dkappa=0 clothoid per non-zero PSF polyline leg",
            "source_vertices_preserved": True,
            "tangent_continuity_at_source_corners": False,
            "physical_orion_encoding_deferred_to_writer": True,
        },
        "counts": dict(counts),
        "maximum_endpoint_error": maximum_endpoint_error,
        "checks": checks,
        "artifact": {
            "path": source_path.name,
            "edges_emitted": emitted,
            "sample_limit": sample_limit,
            "size": source_path.stat().st_size,
            "sha256": _sha256(source_path),
        },
    }
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        "".join(
            f"{_sha256(path)}  {path.name}\n" for path in (source_path, report_path)
        ),
        encoding="ascii",
    )
    if report["status"] != "complete":
        raise PsfError(f"Orion clothoid source checks failed: {checks}")
    _progress("complete", output=output, edges=counts["edges"], segments=counts["segments"])
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=100,
        help="edges to emit after full-corpus validation; 0 emits every edge",
    )
    args = parser.parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"orion-clothoid-export error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
