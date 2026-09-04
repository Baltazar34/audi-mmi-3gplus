#!/usr/bin/env python3
"""Decode and validate Basic PSF world-country official-language lists.

The Basic ``world`` block starts with a compact self-relative record directory.
Each country record ends with a 2- or 3-letter map country code, a count byte,
and that many low-7-bit official-language identifiers.  This is the same
identifier domain stored by the direct SDString decoder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from psf_decode import PsfError, parse_envelope, u16le


SCHEMA_VERSION = 1
WORLD_DIRECTORY_COUNT_OFFSET = 3
WORLD_DIRECTORY_WIDTH_OFFSET = 5
WORLD_DIRECTORY_BASE = 6
COUNTRY_CODE = re.compile(rb"(?<![A-Z])([A-Z]{2,3})\x00")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _decode_directory(world: bytes) -> tuple[int, tuple[int, ...]]:
    if len(world) < WORLD_DIRECTORY_BASE:
        raise PsfError("Basic world block is truncated before its directory")
    count = u16le(world, WORLD_DIRECTORY_COUNT_OFFSET)
    pointer_width = world[WORLD_DIRECTORY_WIDTH_OFFSET] + 1
    if count == 0 or count > 1024:
        raise PsfError(f"implausible world-country record count {count}")
    if pointer_width not in (1, 2, 3, 4):
        raise PsfError(f"unsupported world-country pointer width {pointer_width}")
    directory_end = WORLD_DIRECTORY_BASE + count * pointer_width
    if directory_end > len(world):
        raise PsfError("world-country directory overruns its block")

    starts: list[int] = []
    for index in range(count):
        pointer_at = WORLD_DIRECTORY_BASE + index * pointer_width
        relative = int.from_bytes(
            world[pointer_at : pointer_at + pointer_width], "little"
        )
        starts.append(pointer_at + relative)
    if starts != sorted(set(starts)):
        raise PsfError("world-country record starts are not unique and ordered")
    if starts[0] < directory_end or starts[-1] >= len(world):
        raise PsfError("world-country record start lies outside its data region")
    return pointer_width, tuple(starts)


def _decode_country_trailer(
    world: bytes, record_start: int, record_end: int
) -> dict[str, object]:
    candidates: list[dict[str, object]] = []
    record = world[record_start:record_end]
    for match in COUNTRY_CODE.finditer(record):
        count_at = record_start + match.end()
        if count_at >= record_end:
            continue
        language_count = world[count_at]
        languages_start = count_at + 1
        languages_end = languages_start + language_count
        if not (0 < language_count <= 32 and languages_end <= record_end):
            continue
        if any(world[languages_end:record_end]):
            continue
        identifiers = tuple(world[languages_start:languages_end])
        if any(identifier >= 0x80 for identifier in identifiers):
            continue
        candidates.append(
            {
                "country_code": match.group(1).decode("ascii"),
                "country_code_offset": record_start + match.start(1),
                "language_count_offset": count_at,
                "official_language_identifiers": list(identifiers),
                "official_language_offsets": list(
                    range(languages_start, languages_end)
                ),
            }
        )
    if len(candidates) != 1:
        raise PsfError(
            f"world-country record at relative offset 0x{record_start:x} has "
            f"{len(candidates)} valid trailers"
        )
    return candidates[0]


def decode_world_country_languages(psf: Path) -> dict[str, object]:
    envelope = parse_envelope(psf)
    block = envelope["blocks"]["world"]  # type: ignore[index]
    block_offset = int(block["offset"])  # type: ignore[index]
    block_size = int(block["size"])  # type: ignore[index]
    if block_size == 0:
        raise PsfError("Basic PSF has no world block")
    with psf.open("rb") as source:
        source.seek(block_offset)
        world = source.read(block_size)
    if len(world) != block_size:
        raise PsfError("truncated Basic world block")

    pointer_width, starts = _decode_directory(world)
    countries: list[dict[str, object]] = []
    language_to_countries: dict[int, list[str]] = {}
    for index, record_start in enumerate(starts):
        record_end = starts[index + 1] if index + 1 < len(starts) else len(world)
        country = _decode_country_trailer(world, record_start, record_end)
        country["record_index"] = index
        country["record_relative_offset"] = record_start
        country["record_offset"] = block_offset + record_start
        country["record_end"] = block_offset + record_end
        country["record_size"] = record_end - record_start
        country["country_code_offset"] = block_offset + int(
            country["country_code_offset"]
        )
        country["language_count_offset"] = block_offset + int(
            country["language_count_offset"]
        )
        country["official_language_offsets"] = [
            block_offset + int(offset)
            for offset in country["official_language_offsets"]  # type: ignore[union-attr]
        ]
        countries.append(country)
        code = str(country["country_code"])
        for identifier in country["official_language_identifiers"]:  # type: ignore[union-attr]
            language_to_countries.setdefault(int(identifier), []).append(code)

    return {
        "schema_version": SCHEMA_VERSION,
        "status": "world-country-languages-validated",
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "world": {
            "offset": block_offset,
            "size": block_size,
            "record_count": len(countries),
            "self_relative_pointer_width": pointer_width,
        },
        "countries": countries,
        "language_identifier_to_countries": {
            str(identifier): codes
            for identifier, codes in sorted(language_to_countries.items())
        },
        "evidence": {
            "identifier_domain": (
                "country official-language identifiers; direct SDStrings store "
                "the same low-7-bit identifier and a separate high-bit alternate flag"
            ),
            "country_trailer": (
                "country-code C string, u8 language count, then count low-7-bit "
                "official-language identifiers, followed only by record padding"
            ),
        },
    }


def run(psf: Path, output: Path) -> dict[str, object]:
    report = decode_world_country_languages(psf)
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / "report.json"
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(report_path)
    checksums_path = output / "CHECKSUMS.sha256"
    checksums_path.write_text(
        f"{_sha256(report_path)}  {report_path.name}\n", encoding="ascii"
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_world_country_languages: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "countries": len(report["countries"]),
                "identifiers": sorted(report["language_identifier_to_countries"]),
                "output": str(args.output),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
