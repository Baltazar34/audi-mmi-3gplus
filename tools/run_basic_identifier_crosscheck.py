#!/usr/bin/env python3
"""Cross-check language IDs against Albania and Bosnia Basic PSFs in an archive."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from basic_handle2_name_profile import run as run_profile
from basic_name_semantics import LANGUAGE_LABELS
from basic_world_country_languages import run as run_world_languages
from psf_decode import PsfError


SCHEMA_VERSION = 1
REGIONS: dict[str, dict[str, object]] = {
    "albania": {
        "member": "Mib1/NavDB/Albania_eu/0/default/Albania_Basic.psf",
        "expected_identifiers": {31},
    },
    "bosnia": {
        "member": (
            "Mib1/NavDB/BosniaHerzegovina_eu/0/default/"
            "BosniaHerzegovina_Basic.psf"
        ),
        "expected_identifiers": {30, 33},
    },
}


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"identifier-crosscheck stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _extract(seven_zip: Path, archive: Path, destination: Path) -> None:
    command = [
        str(seven_zip),
        "x",
        "-y",
        f"-o{destination}",
        str(archive),
        *(str(config["member"]) for config in REGIONS.values()),
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert process.stdout is not None
    for line in process.stdout:
        line = line.rstrip()
        if line:
            print(f"identifier-crosscheck 7z={line}", file=sys.stderr, flush=True)
    status = process.wait()
    if status != 0:
        raise RuntimeError(f"7z extraction failed with exit status {status}")


def run(
    archive: Path,
    output: Path,
    sample_limit: int,
    seven_zip: Path,
) -> dict[str, object]:
    if sample_limit < 0:
        raise ValueError("sample limit must be zero or positive")
    if not seven_zip.is_file():
        raise FileNotFoundError(seven_zip)
    output.mkdir(parents=True, exist_ok=True)

    results: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="audi-mmi-language-") as temporary:
        extracted = Path(temporary)
        _progress("extract", archive=archive)
        _extract(seven_zip, archive, extracted)
        for region, config in REGIONS.items():
            member = str(config["member"])
            psf = extracted / member
            if not psf.is_file():
                raise PsfError(f"archive extraction did not produce {member}")
            _progress("world", region=region)
            world = run_world_languages(psf, output / f"{region}_world")
            _progress("profile", region=region)
            profile = run_profile(
                psf, output / region, sample_limit
            )
            world_ids = {
                int(identifier)
                for identifier in world["language_identifier_to_countries"]  # type: ignore[union-attr]
            }
            profile_ids = {
                int(identifier)
                for identifier in profile["identifiers"]  # type: ignore[union-attr]
            }
            expected = set(config["expected_identifiers"])  # type: ignore[arg-type]
            if world_ids != expected or profile_ids != expected:
                raise PsfError(
                    f"{region} language ID mismatch: world={sorted(world_ids)} "
                    f"profile={sorted(profile_ids)} expected={sorted(expected)}"
                )
            results[region] = {
                "archive_member": member,
                "psf_size": psf.stat().st_size,
                "psf_sha256": _sha256(psf),
                "world_identifiers": sorted(world_ids),
                "profile_identifiers": sorted(profile_ids),
                "world_countries": world["language_identifier_to_countries"],
            }

    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated",
        "archive": {
            "path": str(archive.resolve()),
            "size": archive.stat().st_size,
        },
        "regions": results,
        "resolved_language_identifiers": {
            str(identifier): label
            for identifier, label in sorted(LANGUAGE_LABELS.items())
        },
        "validation": {
            "albania_world_and_name_corpus_are_only_identifier_31": True,
            "bosnia_world_and_name_corpus_are_identifiers_30_and_33": True,
        },
    }
    report_path = output / "crosscheck_report.json"
    temporary_report = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary_report.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_report.replace(report_path)
    (output / "CROSSCHECK_CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n", encoding="ascii"
    )
    _progress("complete", output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-limit", type=int, default=20)
    default_7z = shutil.which("7z") or "7z"
    parser.add_argument("--seven-zip", type=Path, default=Path(default_7z))
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.archive, args.output, args.sample_limit, args.seven_zip)
    except (OSError, PsfError, RuntimeError, ValueError) as error:
        print(f"run_basic_identifier_crosscheck: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "identifiers": report["resolved_language_identifiers"],
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
