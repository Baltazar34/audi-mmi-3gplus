#!/usr/bin/env python3
"""Run the complete, self-validating Basic language/name stage."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from basic_graph_export import run as run_graph
from basic_handle2_name_profile import run as run_profile
from basic_world_country_languages import run as run_world_languages
from psf_decode import PsfError


SCHEMA_VERSION = 1


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"basic-name-stage stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _identifier(value: str) -> int:
    identifier = int(value, 0)
    if not 0 <= identifier < 0x80:
        raise argparse.ArgumentTypeError("identifier must fit in the low 7 bits")
    return identifier


def run(
    psf: Path,
    output: Path,
    sample_limit: int,
    transliterate_identifiers: frozenset[int],
) -> dict[str, object]:
    if sample_limit < 0:
        raise ValueError("sample limit must be zero or positive")
    output.mkdir(parents=True, exist_ok=True)

    _progress("world-languages")
    world = run_world_languages(psf, output / "world_languages")
    _progress("name-profile")
    profile = run_profile(psf, output / "name_profile", sample_limit)

    world_identifiers = {
        int(identifier)
        for identifier in world["language_identifier_to_countries"]  # type: ignore[union-attr]
    }
    profile_identifiers = {
        int(identifier) for identifier in profile["identifiers"]  # type: ignore[union-attr]
    }
    missing_from_world = sorted(profile_identifiers - world_identifiers)
    if missing_from_world:
        raise PsfError(
            "direct-name language identifier absent from world-country official "
            f"lists: {missing_from_world[0]}"
        )

    _progress(
        "graph",
        transliterate=",".join(map(str, sorted(transliterate_identifiers)))
        or "none",
    )
    graph = run_graph(
        psf,
        output / "graph",
        sample_limit,
        transliterate_identifiers,
    )
    if graph["status"] != "validated":
        raise PsfError(f"graph stage returned {graph['status']}")

    profile_counts = profile["counts"]
    graph_counts = graph["counts"]
    assert isinstance(profile_counts, dict) and isinstance(graph_counts, dict)
    if profile_counts["edge_logical_name_references"] != graph_counts[
        "edge_logical_name_references"
    ]:
        raise PsfError("name-profile and graph logical-name totals disagree")

    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated",
        "input": world["input"],
        "language_identifiers": {
            identifier: profile["identifiers"][identifier]["language"]  # type: ignore[index]
            for identifier in sorted(profile["identifiers"], key=int)  # type: ignore[arg-type]
        },
        "transliterate_identifiers": sorted(transliterate_identifiers),
        "counts": {
            "countries": len(world["countries"]),  # type: ignore[arg-type]
            "clusters": profile_counts["clusters"],
            "edges": graph_counts["edges"],
            "physical_name_entries": profile_counts["unique_entries"],
            "logical_names": profile_counts["logical_names"],
            "transliteration_pairs": profile_counts["transliteration_pairs"],
            "edge_logical_name_references": profile_counts[
                "edge_logical_name_references"
            ],
        },
        "validation": {
            "all_direct_name_identifiers_are_official_world_languages": True,
            "all_alternates_pair_with_same_identifier_base": True,
            "graph_validated": True,
            "profile_graph_logical_name_counts_match": True,
        },
        "artifacts": {
            "world_languages": "world_languages/report.json",
            "name_profile": "name_profile/report.json",
            "graph": "graph/report.json",
        },
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n", encoding="ascii"
    )
    _progress("complete", output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-limit", type=int, default=100)
    parser.add_argument(
        "--transliterate-identifier",
        action="append",
        type=_identifier,
        default=[],
        metavar="ID",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(
            args.psf,
            args.output,
            args.sample_limit,
            frozenset(args.transliterate_identifier),
        )
    except (OSError, PsfError, ValueError) as error:
        print(f"run_basic_name_stage: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "identifiers": report["language_identifiers"],
                "output": str(args.output),
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
