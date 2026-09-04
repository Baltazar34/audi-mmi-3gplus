#!/usr/bin/env python3
"""Compare raw 64-bit VidTable.AtlasIds with graph Item.Identifiers."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import lzma
from pathlib import Path
import struct
import sys
import zlib

from orion_column_codec import validate_code1_payload_roundtrip
from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
)
from orion_schema_name_inventory import block_index


def read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def raw_u64_values(payload: bytes) -> list[int]:
    """Decode physical type-0x26 storage without truncating it to low 32 bits."""
    if len(payload) % 8:
        raise ValueError("AtlasIds payload is not 64-bit aligned")
    return [struct.unpack_from("<Q", payload, at)[0] for at in range(0, len(payload), 8)]


def worker(
    job: tuple[str, list[tuple[int, int, str]], set[int], set[int]]
) -> dict[str, object]:
    atlas_name, blocks, item_u64, item_low = job
    full_hits: Counter[int] = Counter()
    low_hits: Counter[int] = Counter()
    chunks = dictionary_values = chunk_decompression_failures = 0
    with Path(atlas_name).open("rb") as source:
        for offset, size, _ in blocks:
            source.seek(offset)
            block = source.read(size)
            chunk_info = _parse_chunks(block)
            if chunk_info is None:
                continue
            kind, pairs, cursor = chunk_info
            for compressed_size, uncompressed_size in pairs:
                compressed = block[cursor : cursor + compressed_size]
                cursor += compressed_size
                if not compressed_size:
                    continue
                try:
                    decoded = _decompress(kind, compressed, uncompressed_size)
                except (EOFError, lzma.LZMAError, ValueError, zlib.error):
                    # The block scanner deliberately accepts broad chunk signatures;
                    # unsupported/false-positive candidates are non-fatal unless they
                    # decode far enough to identify a VidTable (whose errors raise).
                    chunk_decompression_failures += 1
                    continue
                schema = parse_logical_schema(decoded)
                if schema is None or schema["map_name"] != "VidTable":
                    continue
                table = parse_exact_column_table(decoded, schema)
                if table is None:
                    raise ValueError(f"VidTable at 0x{offset:x} lacks exact table")
                layouts = validate_code1_payload_roundtrip(
                    decoded,
                    int(schema["data_offset"]),
                    table["descriptors"],
                    table["compression_codes"],
                )
                group = next(
                    row
                    for row in group_serialized_parts(schema, table["descriptors"])
                    if row["composite_name"] == "VidTable"
                    and row["member_name"] == "AtlasIds"
                )
                value_part = int(group["part_start"]) + 1
                descriptor = table["descriptors"][value_part]
                if int(descriptor["type_code"]) != 0x26:
                    raise ValueError("AtlasIds value part is not physical type 0x26")
                layout = layouts[value_part]
                payload = decoded[
                    layout.payload_offset : layout.payload_offset + layout.payload_size
                ]
                values = raw_u64_values(payload)
                chunks += 1
                dictionary_values += len(values)
                for value in values:
                    if value in item_u64:
                        full_hits[value] += 1
                    if (value & 0xFFFFFFFF) in item_low:
                        low_hits[value] += 1
    return {
        "chunks": chunks,
        "dictionary_values": dictionary_values,
        "chunk_decompression_failures": chunk_decompression_failures,
        "full_hits": dict(full_hits),
        "low_hits": dict(low_hits),
    }


def run(atlas: Path, identifiers_path: Path, output: Path, jobs: int) -> dict[str, object]:
    item_rows = read_jsonl(identifiers_path)
    by_u64: dict[int, list[dict[str, object]]] = {}
    for row in item_rows:
        by_u64.setdefault(int(row["identifier_u64"]), []).append(row)
    item_u64 = set(by_u64)
    item_low = {value & 0xFFFFFFFF for value in item_u64}
    blocks = block_index(atlas)
    assignments = [blocks[index::jobs] for index in range(jobs) if blocks[index::jobs]]
    print(
        f"orion-vidtable-ids stage=start blocks={len(blocks)} item_ids={len(item_u64)} jobs={len(assignments)}",
        file=sys.stderr,
        flush=True,
    )
    results: list[dict[str, object]] = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = [
            pool.submit(worker, (str(atlas), assignment, item_u64, item_low))
            for assignment in assignments
        ]
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            print(
                f"orion-vidtable-ids stage=worker-complete workers={completed}/{len(futures)}",
                file=sys.stderr,
                flush=True,
            )
    full_hits: Counter[int] = Counter()
    low_hits: Counter[int] = Counter()
    for result in results:
        full_hits.update({int(key): int(value) for key, value in result["full_hits"].items()})
        low_hits.update({int(key): int(value) for key, value in result["low_hits"].items()})
    rows = [
        {
            "identifier_u64": value,
            "identifier_hex": f"0x{value:016x}",
            "vidtable_occurrences": full_hits[value],
            "item_occurrences": len(by_u64[value]),
            "item_members": [
                {
                    "block_offset": row["block_offset"],
                    "class": row["class"],
                    "class_row": row["class_row"],
                }
                for row in by_u64[value]
            ],
        }
        for value in sorted(full_hits)
    ]
    checks = {
        "all_blocks_assigned": sum(len(assignment) for assignment in assignments) == len(blocks),
        "vidtable_chunks_found": sum(int(row["chunks"]) for row in results) > 0,
        "full_matches_are_item_identifiers": set(full_hits) <= item_u64,
    }
    if not all(checks.values()):
        raise ValueError(f"VidTable identifier checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    matches_path = output / "full_u64_matches.jsonl"
    report_path = output / "report.json"
    matches_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8"
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "atlas": str(atlas),
        "jobs": jobs,
        "blocks": len(blocks),
        "vidtable_chunks": sum(int(row["chunks"]) for row in results),
        "atlas_id_dictionary_rows": sum(int(row["dictionary_values"]) for row in results),
        "nonfatal_chunk_decompression_failures": sum(
            int(row["chunk_decompression_failures"]) for row in results
        ),
        "item_identifier_unique_u64": len(item_u64),
        "full_u64_matching_identifiers": len(full_hits),
        "full_u64_matching_item_rows": sum(len(by_u64[value]) for value in full_hits),
        "full_u64_vidtable_occurrences": sum(full_hits.values()),
        "low_u32_candidate_atlas_ids": len(low_hits),
        "interpretation": (
            "Exact full-u64 overlap proves Item.Identifiers and VidTable.AtlasIds share an ID "
            "domain; low-u32-only overlap is reported separately and is not sufficient proof."
        ),
        "checks": checks,
        "artifacts": {"full_u64_matches": matches_path.name},
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(matches_path)}  {matches_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    print(
        f"orion-vidtable-ids stage=complete vidtables={report['vidtable_chunks']} "
        f"full_matches={len(full_hits)} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--identifiers", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    try:
        report = run(args.atlas, args.identifiers, args.output, args.jobs)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-vidtable-ids error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
