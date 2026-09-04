#!/usr/bin/env python3
"""Inventory logical schema names across an Orion ATLAS in parallel."""

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

from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    _read_name,
    parse_logical_schema,
)


TOKENS = ("name", "road", "route", "street", "class", "category", "functional", "form", "identifier")


def parse_legacy_logical_schema(data: bytes) -> dict[str, object] | None:
    """Parse the CTY direct-container schema variant without annotations."""
    try:
        cursor = 0
        name_length = data[cursor]
        cursor += 1
        if not 1 <= name_length <= 63:
            return None
        map_name = data[cursor : cursor + name_length].decode("ascii")
        cursor += name_length
        header_values = struct.unpack_from("<5I", data, cursor)
        cursor += 20
        composite_count = struct.unpack_from("<H", data, cursor)[0]
        cursor += 2
        if not 1 <= composite_count <= 4096:
            return None
        composites: list[dict[str, object]] = []
        for index in range(composite_count):
            kind = data[cursor]
            cursor += 1
            if kind not in (1, 2, 3):
                return None
            length = data[cursor]
            cursor += 1
            name = data[cursor : cursor + length].decode("ascii")
            cursor += length
            base_index: int | None = None
            if kind == 1:
                base_index = struct.unpack_from("<H", data, cursor)[0]
                cursor += 2
                if base_index != 0xFFFF and base_index >= index:
                    return None
            row_count = struct.unpack_from("<I", data, cursor)[0]
            cursor += 4
            member_count = data[cursor]
            cursor += 1
            composites.append(
                {
                    "index": index,
                    "kind": kind,
                    "name": name,
                    "base_index": base_index,
                    "row_count": row_count,
                    "member_count": member_count,
                    "members": [],
                }
            )
        for composite in composites:
            members: list[dict[str, object]] = []
            for member_index in range(int(composite["member_count"])):
                member_kind = data[cursor]
                cursor += 1
                if member_kind not in (1, 2):
                    return None
                member_name: str | None = None
                if member_kind == 1:
                    length = data[cursor]
                    cursor += 1
                    member_name = data[cursor : cursor + length].decode("ascii")
                    cursor += length
                type_code = data[cursor]
                cursor += 1
                type_composite_index: int | None = None
                if type_code > 0xAF:
                    type_composite_index = struct.unpack_from("<H", data, cursor)[0]
                    cursor += 2
                    if type_composite_index >= composite_count:
                        return None
                optional_flag: int | None = None
                if member_kind == 1:
                    optional_flag = data[cursor]
                    cursor += 1
                members.append(
                    {
                        "index": member_index,
                        "kind": member_kind,
                        "name": member_name,
                        "annotations": [],
                        "type_code": type_code,
                        "type_composite_index": type_composite_index,
                        "optional_flag": optional_flag,
                    }
                )
            composite["members"] = members
        return {
            "map_name": map_name,
            "data_offset": header_values[0],
            "payload_size": header_values[1],
            "header_values": list(header_values),
            "composite_count": composite_count,
            "schema_end": cursor,
            "schema_variant": "legacy-no-member-annotations",
            "composites": composites,
        }
    except (IndexError, UnicodeDecodeError, struct.error):
        return None


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def block_index(atlas: Path) -> list[tuple[int, int, str]]:
    size = atlas.stat().st_size
    rows: list[tuple[int, int, str]] = []
    offset = 0
    with atlas.open("rb") as source:
        while offset < size:
            source.seek(offset)
            header = source.read(0x20)
            name = _read_name(header) if len(header) == 0x20 else None
            block_size = struct.unpack_from("<I", header, 0x10)[0] if len(header) == 0x20 else 0
            if name is None or block_size < 0x20 or offset + block_size > size:
                raise ValueError(f"invalid block at 0x{offset:x}")
            rows.append((offset, block_size, name))
            offset += block_size
    if offset != size:
        raise ValueError("block index does not cover ATLAS exactly")
    return rows


def worker(job: tuple[str, list[tuple[int, int, str]]]) -> dict[str, object]:
    atlas_name, blocks = job
    composite_names: Counter[str] = Counter()
    member_names: Counter[str] = Counter()
    map_names: Counter[str] = Counter()
    candidates: list[dict[str, object]] = []
    chunks = schemas = failures = 0
    with Path(atlas_name).open("rb") as source:
        for offset, size, block_name in blocks:
            source.seek(offset)
            block = source.read(size)
            chunk_info = _parse_chunks(block)
            decoded_items: list[tuple[int, bytes]] = []
            if chunk_info is None:
                direct = block[0x20:]
                if block_name == "CONTAINER" and direct[:1] == b"\x01":
                    direct = direct[1:]
                decoded_items.append((0, direct))
            else:
                kind, pairs, cursor = chunk_info
                for chunk_index, (compressed_size, uncompressed_size) in enumerate(pairs):
                    compressed = block[cursor : cursor + compressed_size]
                    cursor += compressed_size
                    if not compressed_size:
                        continue
                    chunks += 1
                    try:
                        decoded_items.append(
                            (chunk_index, _decompress(kind, compressed, uncompressed_size))
                        )
                    except (EOFError, lzma.LZMAError, ValueError, zlib.error):
                        failures += 1
            for chunk_index, decoded in decoded_items:
                schema = parse_logical_schema(decoded)
                if schema is None:
                    schema = parse_legacy_logical_schema(decoded)
                if schema is None:
                    continue
                schemas += 1
                map_names[str(schema["map_name"])] += 1
                composites = [str(item["name"]) for item in schema["composites"]]
                members = [
                    str(member["name"])
                    for item in schema["composites"]
                    for member in item["members"]
                    if member.get("name") is not None
                ]
                composite_names.update(composites)
                member_names.update(members)
                relevant = sorted(
                    {
                        name
                        for name in composites + members
                        if any(token in name.casefold() for token in TOKENS)
                    }
                )
                if relevant:
                    candidates.append(
                        {
                            "block_offset": offset,
                            "block_offset_hex": f"0x{offset:x}",
                            "block_name": block_name,
                            "chunk_index": chunk_index,
                            "decoded_size": len(decoded),
                            "map_name": schema["map_name"],
                            "relevant_names": relevant,
                            "composites": [
                                {
                                    "name": item["name"],
                                    "row_count": item["row_count"],
                                    "members": [
                                        member.get("name") for member in item["members"]
                                    ],
                                }
                                for item in schema["composites"]
                            ],
                        }
                    )
    return {
        "blocks": len(blocks),
        "chunks": chunks,
        "schemas": schemas,
        "failures": failures,
        "map_names": dict(map_names),
        "composite_names": dict(composite_names),
        "member_names": dict(member_names),
        "candidates": candidates,
    }


def run(atlas: Path, output: Path, jobs: int) -> dict[str, object]:
    if not 1 <= jobs <= 64:
        raise ValueError("jobs must be between 1 and 64")
    blocks = block_index(atlas)
    block_names = Counter(name for _, _, name in blocks)
    block_name_samples: dict[str, list[dict[str, object]]] = {}
    for offset, size, name in blocks:
        samples = block_name_samples.setdefault(name, [])
        if len(samples) < 8:
            samples.append({"offset": offset, "offset_hex": f"0x{offset:x}", "size": size})
    assignments = [blocks[index::jobs] for index in range(jobs) if blocks[index::jobs]]
    print(
        f"orion-schema-inventory stage=start blocks={len(blocks)} jobs={len(assignments)}",
        file=sys.stderr,
        flush=True,
    )
    results: list[dict[str, object]] = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(worker, (str(atlas), assignment)) for assignment in assignments]
        for completed, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            print(
                f"orion-schema-inventory stage=worker-complete workers={completed}/{len(futures)}",
                file=sys.stderr,
                flush=True,
            )
    map_names: Counter[str] = Counter()
    composite_names: Counter[str] = Counter()
    member_names: Counter[str] = Counter()
    candidates: list[dict[str, object]] = []
    for result in results:
        map_names.update(result["map_names"])
        composite_names.update(result["composite_names"])
        member_names.update(result["member_names"])
        candidates.extend(result["candidates"])
    candidates.sort(key=lambda row: (int(row["block_offset"]), int(row["chunk_index"])))
    checks = {
        "all_blocks_assigned": sum(int(result["blocks"]) for result in results) == len(blocks),
        "schema_scan_completed": True,
    }
    if not all(checks.values()):
        raise ValueError(f"inventory checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    candidates_path = output / "candidates.jsonl"
    report_path = output / "report.json"
    candidates_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in candidates), encoding="utf-8"
    )
    report = {
        "schema_version": 1,
        "status": "complete",
        "atlas": str(atlas),
        "jobs": jobs,
        "blocks": len(blocks),
        "block_names": dict(sorted(block_names.items())),
        "block_name_samples": dict(sorted(block_name_samples.items())),
        "decoded_chunks": sum(int(result["chunks"]) for result in results),
        "logical_schema_chunks": sum(int(result["schemas"]) for result in results),
        "chunk_decompression_failures": sum(
            int(result["failures"]) for result in results
        ),
        "candidate_schema_chunks": len(candidates),
        "map_names": dict(sorted(map_names.items())),
        "composite_names": dict(sorted(composite_names.items())),
        "member_names": dict(sorted(member_names.items())),
        "checks": checks,
        "artifacts": {"candidates": candidates_path.name},
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "CHECKSUMS.sha256").write_text(
        f"{sha256(candidates_path)}  {candidates_path.name}\n"
        f"{sha256(report_path)}  {report_path.name}\n",
        encoding="ascii",
    )
    print(
        f"orion-schema-inventory stage=complete schemas={report['logical_schema_chunks']} "
        f"candidates={len(candidates)} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    try:
        report = run(args.atlas, args.output, args.jobs)
    except (OSError, TypeError, ValueError) as error:
        print(f"orion-schema-inventory error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
