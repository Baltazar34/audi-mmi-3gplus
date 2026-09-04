#!/usr/bin/env python3
"""Decode and validate VidTable row-to-AtlasId/XacVectorOffset mappings."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import lzma
from pathlib import Path
import sys
import zlib

from orion_column_codec import unpack_code1_values, validate_code1_payload_roundtrip
from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
)
from orion_schema_name_inventory import block_index
from orion_vidtable_identifier_profile import raw_u64_values


def payload_for(decoded: bytes, layout: object) -> bytes:
    return decoded[layout.payload_offset : layout.payload_offset + layout.payload_size]


def unsigned_values(decoded: bytes, layout: object, count: int) -> list[int]:
    return unpack_code1_values(
        layout.type_code, payload_for(decoded, layout), count, signed=False
    )


def decode_vidtable_rows(
    decoded: bytes, schema: dict[str, object], table: dict[str, object]
) -> tuple[list[int], list[int], dict[str, object]]:
    """Return parallel AtlasId/XAC-offset rows and strict layout evidence."""
    layouts = validate_code1_payload_roundtrip(
        decoded,
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    groups = group_serialized_parts(schema, table["descriptors"])
    by_name = {group["member_name"]: group for group in groups if group["member_name"]}
    try:
        xac_group = by_name["XacVectorOffsets"]
        atlas_group = by_name["AtlasIds"]
    except KeyError as error:
        raise ValueError(f"VidTable lacks {error.args[0]} group") from error
    if int(xac_group["part_count"]) != 2 or int(atlas_group["part_count"]) != 2:
        raise ValueError("VidTable optional vectors must have count and value parts")

    xac_start = int(xac_group["part_start"])
    atlas_start = int(atlas_group["part_start"])
    xac_count_values = unsigned_values(decoded, layouts[xac_start], 1)
    atlas_count_values = unsigned_values(decoded, layouts[atlas_start], 1)
    row_count = xac_count_values[0]
    if atlas_count_values != [row_count]:
        raise ValueError("AtlasIds and XacVectorOffsets counts differ")
    offsets = unsigned_values(decoded, layouts[xac_start + 1], row_count)

    atlas_descriptor = table["descriptors"][atlas_start + 1]
    atlas_payload = payload_for(decoded, layouts[atlas_start + 1])
    dictionary = raw_u64_values(atlas_payload)
    tag = int(atlas_descriptor["tag"])
    if tag == 2:
        if len(dictionary) != row_count:
            raise ValueError("direct AtlasIds value count differs from row count")
        atlas_ids = dictionary
        variant = "direct"
        index_min = index_max = None
    elif tag == 3:
        dictionary_count = int(atlas_descriptor["indirect_count"])
        if len(dictionary) != dictionary_count:
            raise ValueError("indirect AtlasIds dictionary size mismatch")
        mapping_member = int(atlas_descriptor["member_index"])
        mapping_groups = [
            group
            for group in groups
            if int(group["composite_index"]) == int(atlas_group["composite_index"])
            and int(group["member_index"]) == mapping_member
        ]
        if len(mapping_groups) != 1 or int(mapping_groups[0]["part_count"]) != 1:
            raise ValueError("indirect AtlasIds mapping column is not unique")
        mapping_part = int(mapping_groups[0]["part_start"])
        indices = unsigned_values(decoded, layouts[mapping_part], row_count)
        if indices and max(indices) >= dictionary_count:
            raise ValueError("indirect AtlasIds index exceeds dictionary")
        atlas_ids = [dictionary[index] for index in indices]
        variant = "indirect"
        index_min = min(indices) if indices else None
        index_max = max(indices) if indices else None
    else:
        raise ValueError(f"unsupported AtlasIds descriptor tag {tag}")

    if len(atlas_ids) != len(offsets) or len(offsets) != row_count:
        raise ValueError("expanded VidTable columns are not row-aligned")
    return atlas_ids, offsets, {
        "variant": variant,
        "row_count": row_count,
        "dictionary_count": len(dictionary),
        "index_min": index_min,
        "index_max": index_max,
        "xac_offset_min": min(offsets) if offsets else None,
        "xac_offset_max": max(offsets) if offsets else None,
        "xac_offsets_unique": len(offsets) == len(set(offsets)),
    }


def read_identifier_set(path: Path) -> set[int]:
    values: set[int] = set()
    with path.open(encoding="utf-8") as source:
        for line in source:
            values.add(int(json.loads(line)["identifier_u64"]))
    return values


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def worker(job: tuple[str, list[tuple[int, int, str]], set[int]]) -> dict[str, object]:
    atlas_name, blocks, selected_ids = job
    tables: list[dict[str, object]] = []
    selected_rows: list[dict[str, object]] = []
    failures = 0
    with Path(atlas_name).open("rb") as source:
        for block_offset, size, _ in blocks:
            source.seek(block_offset)
            block = source.read(size)
            chunk_info = _parse_chunks(block)
            if chunk_info is None:
                continue
            kind, pairs, cursor = chunk_info
            for chunk_index, (compressed_size, uncompressed_size) in enumerate(pairs):
                compressed = block[cursor : cursor + compressed_size]
                cursor += compressed_size
                if not compressed_size:
                    continue
                try:
                    decoded = _decompress(kind, compressed, uncompressed_size)
                except (EOFError, lzma.LZMAError, ValueError, zlib.error):
                    failures += 1
                    continue
                schema = parse_logical_schema(decoded)
                if schema is None or schema["map_name"] != "VidTable":
                    continue
                table = parse_exact_column_table(decoded, schema)
                if table is None:
                    raise ValueError(f"VidTable at 0x{block_offset:x} lacks exact table")
                atlas_ids, offsets, profile = decode_vidtable_rows(decoded, schema, table)
                profile.update(
                    {
                        "block_offset": block_offset,
                        "block_offset_hex": f"0x{block_offset:x}",
                        "chunk_index": chunk_index,
                    }
                )
                tables.append(profile)
                for row_index, (atlas_id, xac_offset) in enumerate(zip(atlas_ids, offsets)):
                    if atlas_id in selected_ids:
                        selected_rows.append(
                            {
                                "atlas_id_u64": atlas_id,
                                "atlas_id_hex": f"0x{atlas_id:016x}",
                                "block_offset": block_offset,
                                "chunk_index": chunk_index,
                                "row_index": row_index,
                                "xac_vector_offset": xac_offset,
                                "mapping_variant": profile["variant"],
                            }
                        )
    return {"tables": tables, "selected_rows": selected_rows, "failures": failures}


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def run(atlas: Path, identifiers: Path, output: Path, jobs: int) -> dict[str, object]:
    if jobs < 1:
        raise ValueError("jobs must be positive")
    selected_ids = read_identifier_set(identifiers)
    blocks = block_index(atlas)
    assignments = [blocks[index::jobs] for index in range(jobs) if blocks[index::jobs]]
    print(
        f"orion-vidtable-rows stage=start blocks={len(blocks)} selected_ids={len(selected_ids)} jobs={len(assignments)}",
        file=sys.stderr,
        flush=True,
    )
    results: list[dict[str, object]] = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = [
            pool.submit(worker, (str(atlas), assignment, selected_ids))
            for assignment in assignments
        ]
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            print(
                f"orion-vidtable-rows stage=worker-complete workers={completed}/{len(futures)}",
                file=sys.stderr,
                flush=True,
            )
    tables = sorted(
        (row for result in results for row in result["tables"]),
        key=lambda row: (int(row["block_offset"]), int(row["chunk_index"])),
    )
    selected_rows = sorted(
        (row for result in results for row in result["selected_rows"]),
        key=lambda row: (
            int(row["block_offset"]),
            int(row["chunk_index"]),
            int(row["row_index"]),
        ),
    )
    variants = Counter(str(row["variant"]) for row in tables)
    total_rows = sum(int(row["row_count"]) for row in tables)
    checks = {
        "all_blocks_assigned": sum(map(len, assignments)) == len(blocks),
        "vidtable_chunks_found": bool(tables),
        "all_expanded_rows_aligned": total_rows > 0,
        "all_xac_offsets_unique_within_table": all(
            bool(row["xac_offsets_unique"]) for row in tables
        ),
        "selected_rows_are_requested_ids": all(
            int(row["atlas_id_u64"]) in selected_ids for row in selected_rows
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"VidTable row checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    tables_path = output / "tables.jsonl"
    selected_path = output / "selected_item_rows.jsonl"
    report_path = output / "report.json"
    write_jsonl(tables_path, tables)
    write_jsonl(selected_path, selected_rows)
    report = {
        "schema_version": 1,
        "status": "complete",
        "atlas": str(atlas),
        "blocks": len(blocks),
        "jobs": len(assignments),
        "vidtable_chunks": len(tables),
        "expanded_rows": total_rows,
        "mapping_variants": dict(sorted(variants.items())),
        "selected_identifier_count": len(selected_ids),
        "selected_matching_rows": len(selected_rows),
        "selected_matching_unique_ids": len(
            {int(row["atlas_id_u64"]) for row in selected_rows}
        ),
        "nonfatal_chunk_decompression_failures": sum(
            int(result["failures"]) for result in results
        ),
        "checks": checks,
        "interpretation": (
            "Each expanded row is an exact index-aligned AtlasId/XacVectorOffset pair; "
            "indirect AtlasIds were resolved through their explicit dictionary index column."
        ),
        "artifacts": {
            "tables": tables_path.name,
            "selected_item_rows": selected_path.name,
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        "".join(
            f"{sha256(path)}  {path.name}\n"
            for path in (tables_path, selected_path, report_path)
        ),
        encoding="ascii",
    )
    print(
        f"orion-vidtable-rows stage=complete vidtables={len(tables)} rows={total_rows} "
        f"selected={len(selected_rows)} checks=all-pass",
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
        print(f"orion-vidtable-rows error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
