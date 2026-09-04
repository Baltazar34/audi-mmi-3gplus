#!/usr/bin/env python3
"""Run one resumable Orion-to-MIB spatial corpus stage end to end."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(stage: str, command: list[str]) -> None:
    print(f"orion-cross-version stage={stage} status=start", file=sys.stderr, flush=True)
    subprocess.run(command, check=True)
    print(f"orion-cross-version stage={stage} status=complete", file=sys.stderr, flush=True)


def load_report(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--atlas", type=Path, required=True)
    parser.add_argument("--mib-psf", type=Path, required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--start-offset", required=True)
    parser.add_argument("--bbox", type=float, nargs=4, required=True)
    parser.add_argument("--match-limit", type=int, default=64)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--output-root", type=Path, default=Path("out"))
    parser.add_argument(
        "--mib-corpus",
        type=Path,
        help="Reuse an existing mib_graph_spatial output directory for the same bbox.",
    )
    args = parser.parse_args()
    tools = Path(__file__).resolve().parent
    python = sys.executable
    root = args.output_root
    probe = root / f"orion_graph_spatial_probe_{args.label}"
    properties = root / f"orion_edge_properties_{args.label}"
    edge_source = root / f"orion_edge_source_{args.label}"
    centerlines = root / f"orion_centerline_source_{args.label}"
    corridor = root / f"orion_mib_corridor_matches_{args.label}"
    bounded = root / f"orion_mib_bounded_graph_{args.label}"
    values = root / f"orion_mib_property_values_{args.label}"
    directions = root / f"orion_mib_direction_{args.label}"
    mib_corpus = args.mib_corpus or root / f"mib_graph_spatial_{args.label}"
    try:
        run_command(
            "probe",
            [
                python,
                str(tools / "orion_graph_spatial_probe.py"),
                str(args.atlas),
                "--output",
                str(probe),
                "--bbox",
                *(str(value) for value in args.bbox),
                "--match-limit",
                str(args.match_limit),
                "--start-offset",
                args.start_offset,
                "--save-decoded",
            ],
        )
        run_command(
            "properties",
            [python, str(tools / "orion_edge_property_decode.py"), str(probe), "--output", str(properties)],
        )
        run_command(
            "edge-source",
            [
                python,
                str(tools / "orion_edge_geometry_decode.py"),
                str(probe),
                "--properties",
                str(properties / "edges.properties.jsonl"),
                "--output",
                str(edge_source),
            ],
        )
        run_command(
            "centerlines",
            [
                python,
                str(tools / "orion_centerline_geometry_decode.py"),
                str(probe),
                "--edge-source",
                str(edge_source / "edges.source.jsonl"),
                "--output",
                str(centerlines),
                "--jobs",
                str(args.jobs),
            ],
        )
        if args.mib_corpus is None:
            run_command(
                "mib-spatial",
                [
                    python,
                    str(tools / "mib_graph_spatial_extract.py"),
                    str(args.mib_psf),
                    "--output",
                    str(mib_corpus),
                    "--bbox",
                    *(str(value) for value in args.bbox),
                    "--jobs",
                    str(args.jobs),
                ],
            )
        if not (mib_corpus / "edges.jsonl").is_file():
            raise FileNotFoundError(mib_corpus / "edges.jsonl")
        run_command(
            "corridor",
            [
                python,
                str(tools / "orion_mib_corridor_match.py"),
                str(centerlines / "edges.centerlines.jsonl"),
                str(mib_corpus / "edges.jsonl"),
                "--output",
                str(corridor),
                "--jobs",
                str(args.jobs),
                "--radius-metres",
                "80",
            ],
        )
        run_command(
            "bounded",
            [
                python,
                str(tools / "orion_mib_bounded_graph_match.py"),
                str(corridor / "matches.jsonl"),
                str(centerlines / "edges.centerlines.jsonl"),
                str(mib_corpus / "edges.jsonl"),
                "--output",
                str(bounded),
                "--jobs",
                str(args.jobs),
                "--corridor-metres",
                "80",
                "--max-hops",
                "12",
            ],
        )
        run_command(
            "property-values",
            [
                python,
                str(tools / "orion_mib_property_value_profile.py"),
                "--bounded",
                str(bounded / "matches.jsonl"),
                "--properties",
                str(properties / "edges.properties.jsonl"),
                "--mib",
                str(mib_corpus / "edges.jsonl"),
                "--output",
                str(values),
            ],
        )
        run_command(
            "directions",
            [
                python,
                str(tools / "orion_mib_direction_profile.py"),
                "--bounded",
                str(bounded / "matches.jsonl"),
                "--original",
                str(centerlines / "edges.centerlines.jsonl"),
                "--properties",
                str(properties / "edges.properties.jsonl"),
                "--mib",
                str(mib_corpus / "edges.jsonl"),
                "--output",
                str(directions),
            ],
        )
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"orion-cross-version error={error}", file=sys.stderr)
        return 1
    probe_report = load_report(probe / "report.json")
    property_report = load_report(properties / "report.json")
    centerline_report = load_report(centerlines / "report.json")
    corridor_report = load_report(corridor / "report.json")
    bounded_report = load_report(bounded / "report.json")
    value_report = load_report(values / "report.json")
    direction_report = load_report(directions / "report.json")
    summary = {
        "schema_version": 1,
        "status": "complete",
        "label": args.label,
        "start_offset_hex": probe_report["start_offset_hex"],
        "next_block_offset_hex": probe_report["next_block_offset_hex"],
        "chunks": probe_report["matching_chunks"],
        "edges": property_report["edges"],
        "point_lld_rows": centerline_report["point_lld_rows"],
        "corridor_confidence_counts": corridor_report["confidence_counts"],
        "bounded_confidence_counts": bounded_report["confidence_counts"],
        "property_value_paths": value_report["accepted_paths"],
        "direction_path_modes": direction_report["mib_path_modes_relative_to_original"],
        "checks": {"all_stages_complete": True},
    }
    summary_path = root / f"orion_cross_version_{args.label}.json"
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (root / f"orion_cross_version_{args.label}.sha256").write_text(
        f"{sha256(summary_path)}  {summary_path.name}\n", encoding="ascii"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
