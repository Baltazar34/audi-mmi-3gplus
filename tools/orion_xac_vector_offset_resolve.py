#!/usr/bin/env python3
"""Resolve VidTable XacVectorOffsets through the firmware-defined XAC header modes."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

from orion_column_codec import unpack_code1_values, validate_code1_payload_roundtrip
from orion_psd_reference_profile import (
    _decompress,
    _parse_chunks,
    group_serialized_parts,
    parse_exact_column_table,
    parse_logical_schema,
)
from orion_schema_name_inventory import block_index


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source]


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, sort_keys=True) + "\n")


def vector_header(
    data: bytes | mmap.mmap, marker_offset: int, physical_bound: int
) -> dict[str, int | str | None]:
    """Parse the fields used by NavCore's XAC vector lookup."""
    if physical_bound < 22 or marker_offset + physical_bound > len(data):
        raise ValueError("XAC vector block is too short for its header")
    version = struct.unpack_from(">H", data, marker_offset + 20)[0]
    if version > 4 and physical_bound < 116:
        raise ValueError("version-five XAC vector block lacks its extended header")
    index_flag = struct.unpack_from(">H", data, marker_offset + 114)[0] if version > 4 else 0
    if index_flag == 0:
        return {
            "version": version,
            "mode": "direct",
            "index_flag": 0,
            "index_table_offset": None,
            "index_count": None,
        }
    if index_flag != 1:
        raise ValueError(f"unsupported XAC vector index flag {index_flag}")
    table_offset = struct.unpack_from(">I", data, marker_offset + 108)[0]
    index_count = struct.unpack_from(">H", data, marker_offset + 112)[0]
    if table_offset + index_count * 2 > physical_bound:
        raise ValueError("XAC vector index table exceeds physical block bound")
    return {
        "version": version,
        "mode": "indexed",
        "index_flag": index_flag,
        "index_table_offset": table_offset,
        "index_count": index_count,
    }


def resolve_vector_offset(
    data: bytes | mmap.mmap,
    marker_offset: int,
    physical_bound: int,
    header: dict[str, int | str | None],
    vector_offset: int,
) -> int:
    """Apply the direct or indexed formula recovered from NavCore."""
    if vector_offset < 0:
        raise ValueError("negative XAC vector offset")
    if header["mode"] == "direct":
        resolved = vector_offset
    else:
        if vector_offset & 1:
            raise ValueError("indexed XAC vector offset is not even")
        index = vector_offset >> 1
        index_count = int(header["index_count"])
        if index >= index_count:
            raise ValueError("XAC vector offset exceeds index table")
        table_offset = int(header["index_table_offset"])
        encoded = struct.unpack_from(
            ">H", data, marker_offset + table_offset + vector_offset
        )[0]
        resolved = encoded * 2
    if resolved >= physical_bound:
        raise ValueError("resolved XAC target exceeds physical block bound")
    return resolved


def decode_offsets(decoded: bytes) -> list[int]:
    schema = parse_logical_schema(decoded)
    if schema is None or schema["map_name"] != "VidTable":
        raise ValueError("selected chunk is not a VidTable")
    table = parse_exact_column_table(decoded, schema)
    if table is None:
        raise ValueError("VidTable lacks an exact physical table")
    layouts = validate_code1_payload_roundtrip(
        decoded,
        int(schema["data_offset"]),
        table["descriptors"],
        table["compression_codes"],
    )
    group = next(
        row
        for row in group_serialized_parts(schema, table["descriptors"])
        if row["member_name"] == "XacVectorOffsets"
    )
    if int(group["part_count"]) != 2:
        raise ValueError("XacVectorOffsets does not have count and value parts")
    count_layout = layouts[int(group["part_start"])]
    count_payload = decoded[
        count_layout.payload_offset : count_layout.payload_offset + count_layout.payload_size
    ]
    counts = unpack_code1_values(count_layout.type_code, count_payload, 1, signed=False)
    value_layout = layouts[int(group["part_start"]) + 1]
    value_payload = decoded[
        value_layout.payload_offset : value_layout.payload_offset + value_layout.payload_size
    ]
    return unpack_code1_values(
        value_layout.type_code, value_payload, counts[0], signed=False
    )


def decoded_chunk(source, block_offset: int, block_size: int, chunk_index: int) -> bytes:
    source.seek(block_offset)
    block = source.read(block_size)
    parsed = _parse_chunks(block)
    if parsed is None:
        raise ValueError(f"block 0x{block_offset:x} has no chunk envelope")
    kind, pairs, cursor = parsed
    for index, (compressed_size, uncompressed_size) in enumerate(pairs):
        compressed = block[cursor : cursor + compressed_size]
        cursor += compressed_size
        if index == chunk_index:
            return _decompress(kind, compressed, uncompressed_size)
    raise ValueError(f"chunk {chunk_index} is absent at block 0x{block_offset:x}")


def candidate_profile(
    candidate: dict[str, object],
    offsets: list[int],
    databases: dict[str, mmap.mmap],
) -> dict[str, object]:
    data = databases[str(candidate["db_path"])]
    marker = int(candidate["marker_offset"])
    bound = int(candidate["physical_upper_bound_distance"])
    try:
        header = vector_header(data, marker, bound)
        resolved_min = None
        resolved_max = None
        signature_failures = 0
        for vector_offset in offsets:
            resolved = resolve_vector_offset(data, marker, bound, header, vector_offset)
            resolved_min = resolved if resolved_min is None else min(resolved_min, resolved)
            resolved_max = resolved if resolved_max is None else max(resolved_max, resolved)
            if data[marker + resolved] & 0xC0 != 0xC0:
                signature_failures += 1
        valid = signature_failures == 0
        error = None
    except (IndexError, struct.error, ValueError) as failure:
        header = None
        resolved_min = resolved_max = None
        signature_failures = None
        valid = False
        error = str(failure)
    return {
        "global_marker_index": int(candidate["global_marker_index"]),
        "db_index": int(candidate["db_index"]),
        "db_path": str(candidate["db_path"]),
        "marker_offset": marker,
        "marker_offset_hex": candidate["marker_offset_hex"],
        "owner_name": candidate["owner_name"],
        "physical_upper_bound_distance": bound,
        "header": header,
        "offset_count": len(offsets),
        "resolved_target_min": resolved_min,
        "resolved_target_max": resolved_max,
        "target_signature_c0_failures": signature_failures,
        "structurally_valid": valid,
        "error": error,
    }


def worker(job: tuple[str, dict[int, int], list[dict[str, object]], dict[int, list[dict[str, object]]]]) -> list[dict[str, object]]:
    atlas_name, sizes, bindings, candidates_by_table = job
    db_files: dict[str, object] = {}
    databases: dict[str, mmap.mmap] = {}
    try:
        for row in bindings:
            choices = candidates_by_table.get(int(row["vidtable_index"]), [row])
            for choice in choices:
                name = str(choice["db_path"])
                if name not in databases:
                    db_files[name] = Path(name).open("rb")
                    databases[name] = mmap.mmap(
                        db_files[name].fileno(), 0, access=mmap.ACCESS_READ
                    )
        results: list[dict[str, object]] = []
        with Path(atlas_name).open("rb") as atlas:
            for row in bindings:
                table_index = int(row["vidtable_index"])
                block_offset = int(row["vidtable_block_offset"])
                chunk_index = int(row["vidtable_chunk_index"])
                decoded = decoded_chunk(
                    atlas, block_offset, sizes[block_offset], chunk_index
                )
                offsets = decode_offsets(decoded)
                if len(offsets) != int(row["row_count"]):
                    raise ValueError(f"VidTable {table_index} row count changed")
                choices = candidates_by_table.get(table_index, [row])
                profiles = [
                    candidate_profile(choice, offsets, databases) for choice in choices
                ]
                results.append(
                    {
                        "vidtable_index": table_index,
                        "vidtable_block_offset": block_offset,
                        "vidtable_chunk_index": chunk_index,
                        "row_count": len(offsets),
                        "xac_offset_min": min(offsets) if offsets else None,
                        "xac_offset_max": max(offsets) if offsets else None,
                        "candidate_profiles": profiles,
                    }
                )
        return results
    finally:
        for data in databases.values():
            data.close()
        for source in db_files.values():
            source.close()


def ordered_prune(rows: list[dict[str, object]]) -> None:
    """Remove structurally valid candidates that cannot occur in global order."""
    previous = -1
    for row in rows:
        viable = [
            candidate
            for candidate in row["candidate_profiles"]
            if candidate["structurally_valid"]
            and int(candidate["global_marker_index"]) > previous
        ]
        if not viable:
            raise ValueError(f"VidTable {row['vidtable_index']} has no forward candidate")
        row["candidate_profiles"] = viable
        previous = min(int(candidate["global_marker_index"]) for candidate in viable)
    following = 1 << 62
    for row in reversed(rows):
        viable = [
            candidate
            for candidate in row["candidate_profiles"]
            if int(candidate["global_marker_index"]) < following
        ]
        if not viable:
            raise ValueError(f"VidTable {row['vidtable_index']} has no reverse candidate")
        row["candidate_profiles"] = viable
        following = max(int(candidate["global_marker_index"]) for candidate in viable)


def xac_owner_suffix(name: object) -> str | None:
    value = str(name) if name is not None else ""
    if value.endswith("_1.xac"):
        return "_1.xac"
    if value.endswith("_2.xac"):
        return "_2.xac"
    return None


def apply_proven_owner_invariant(rows: list[dict[str, object]]) -> tuple[str, int]:
    """Use an owner suffix only when every unique named-XAC binding proves it."""
    unique_named = [
        row["candidate_profiles"][0]
        for row in rows
        if len(row["candidate_profiles"]) == 1
        and xac_owner_suffix(row["candidate_profiles"][0]["owner_name"]) is not None
    ]
    suffixes = {xac_owner_suffix(candidate["owner_name"]) for candidate in unique_named}
    if len(suffixes) != 1:
        raise ValueError(f"unique XAC bindings do not prove one owner family: {suffixes}")
    suffix = suffixes.pop()
    assert suffix is not None
    for row in rows:
        if len(row["candidate_profiles"]) == 1:
            continue
        matching = [
            candidate
            for candidate in row["candidate_profiles"]
            if xac_owner_suffix(candidate["owner_name"]) == suffix
        ]
        if matching:
            row["candidate_profiles"] = matching
    return suffix, len(unique_named)


def run(
    atlas: Path,
    bindings_path: Path,
    candidates_path: Path,
    selected_rows_path: Path | None,
    output: Path,
    jobs: int,
) -> dict[str, object]:
    if jobs < 1:
        raise ValueError("jobs must be positive")
    bindings = read_jsonl(bindings_path)
    raw_candidates = read_jsonl(candidates_path)
    candidates_by_table: dict[int, list[dict[str, object]]] = defaultdict(list)
    for candidate in raw_candidates:
        candidates_by_table[int(candidate["vidtable_index"])].append(candidate)
    sizes = {offset: size for offset, size, _ in block_index(atlas)}
    assignments = [bindings[index::jobs] for index in range(jobs) if bindings[index::jobs]]
    print(
        f"orion-xac-offsets stage=start tables={len(bindings)} rows="
        f"{sum(int(row['row_count']) for row in bindings)} jobs={len(assignments)}",
        file=sys.stderr,
        flush=True,
    )
    results: list[dict[str, object]] = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = [
            pool.submit(worker, (str(atlas), sizes, assignment, candidates_by_table))
            for assignment in assignments
        ]
        for complete, future in enumerate(as_completed(futures), 1):
            results.extend(future.result())
            print(
                f"orion-xac-offsets stage=worker-complete workers={complete}/{len(futures)}",
                file=sys.stderr,
                flush=True,
            )
    profiles = sorted(results, key=lambda row: int(row["vidtable_index"]))
    ordered_prune(profiles)
    for row in profiles:
        row["structural_candidate_count"] = len(row["candidate_profiles"])
    proven_owner_suffix, owner_invariant_support = apply_proven_owner_invariant(profiles)
    ordered_prune(profiles)
    final_bindings: list[dict[str, object]] = []
    unresolved: list[dict[str, object]] = []
    for row in profiles:
        viable = row.pop("candidate_profiles")
        row["final_candidate_count"] = len(viable)
        row["resolved_uniquely"] = len(viable) == 1
        if len(viable) == 1:
            row["binding"] = viable[0]
        else:
            row["binding"] = None
            unresolved.append({**row, "viable_candidates": viable})
        final_bindings.append(row)

    mode_counts = Counter(
        str(row["binding"]["header"]["mode"])
        for row in final_bindings
        if row["binding"] is not None
    )
    total_rows = sum(int(row["row_count"]) for row in final_bindings)
    checks = {
        "all_vidtables_profiled": len(final_bindings) == len(bindings),
        "all_offsets_redecoded": total_rows
        == sum(int(row["row_count"]) for row in bindings),
        "every_table_has_structural_candidate": all(
            int(row["final_candidate_count"]) > 0 for row in final_bindings
        ),
        "all_unique_targets_have_c0_signature": all(
            row["binding"] is None
            or int(row["binding"]["target_signature_c0_failures"]) == 0
            for row in final_bindings
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"XAC offset resolver checks failed: {checks}")
    output.mkdir(parents=True, exist_ok=True)
    tables_output = output / "resolved_tables.jsonl"
    unresolved_output = output / "unresolved_candidates.jsonl"
    report_path = output / "report.json"
    write_jsonl(tables_output, final_bindings)
    write_jsonl(unresolved_output, unresolved)
    selected_target_count = 0
    selected_output = output / "selected_item_targets.jsonl"
    if selected_rows_path is not None:
        table_lookup = {
            (int(row["vidtable_block_offset"]), int(row["vidtable_chunk_index"])): row
            for row in final_bindings
        }
        db_files: dict[str, object] = {}
        databases: dict[str, mmap.mmap] = {}
        try:
            with selected_rows_path.open(encoding="utf-8") as source, selected_output.open(
                "w", encoding="utf-8"
            ) as target:
                for line in source:
                    selected = json.loads(line)
                    key = (int(selected["block_offset"]), int(selected["chunk_index"]))
                    table_row = table_lookup[key]
                    binding = table_row["binding"]
                    if binding is None:
                        raise ValueError("selected Item row belongs to unresolved XAC binding")
                    db_name = str(binding["db_path"])
                    if db_name not in databases:
                        db_files[db_name] = Path(db_name).open("rb")
                        databases[db_name] = mmap.mmap(
                            db_files[db_name].fileno(), 0, access=mmap.ACCESS_READ
                        )
                    data = databases[db_name]
                    marker = int(binding["marker_offset"])
                    resolved = resolve_vector_offset(
                        data,
                        marker,
                        int(binding["physical_upper_bound_distance"]),
                        binding["header"],
                        int(selected["xac_vector_offset"]),
                    )
                    if data[marker + resolved] & 0xC0 != 0xC0:
                        raise ValueError("selected Item target lacks XAC vector signature")
                    selected.update(
                        {
                            "vidtable_index": int(table_row["vidtable_index"]),
                            "xac_db_index": int(binding["db_index"]),
                            "xac_db_path": db_name,
                            "xac_owner_name": binding["owner_name"],
                            "xac_marker_offset": marker,
                            "xac_target_relative_offset": resolved,
                            "xac_target_absolute_offset": marker + resolved,
                            "xac_target_prefix_hex": bytes(
                                data[
                                    marker + resolved : marker
                                    + min(
                                        resolved + 16,
                                        int(binding["physical_upper_bound_distance"]),
                                    )
                                ]
                            ).hex(),
                        }
                    )
                    target.write(json.dumps(selected, sort_keys=True) + "\n")
                    selected_target_count += 1
        finally:
            for data in databases.values():
                data.close()
            for source in db_files.values():
                source.close()
    report = {
        "schema_version": 1,
        "status": "complete",
        "atlas": str(atlas),
        "bindings": str(bindings_path),
        "vidtable_chunks": len(final_bindings),
        "xac_vector_offsets_checked": total_rows,
        "selected_item_targets": selected_target_count,
        "unique_physical_bindings": len(final_bindings) - len(unresolved),
        "unresolved_physical_bindings": len(unresolved),
        "proven_named_xac_owner_suffix": proven_owner_suffix,
        "owner_invariant_unique_support": owner_invariant_support,
        "resolved_header_modes": dict(sorted(mode_counts.items())),
        "jobs": len(assignments),
        "checks": checks,
        "firmware_formula": {
            "direct": "target = marker + XacVectorOffset",
            "indexed": (
                "index = XacVectorOffset / 2; target = marker + "
                "2 * BE16(marker + BE32(marker+0x6c) + XacVectorOffset)"
            ),
            "mode": "version=BE16(+0x14); indexed when version>4 and BE16(+0x72)==1",
        },
        "interpretation": (
            "Offsets resolve to XAC vector starts whose first byte has the firmware-tested "
            "0xc0 vector signature. Structural validation, the owner family proved by all "
            "pre-existing unique named-XAC matches, and global order resolve every block."
        ),
        "artifacts": {
            "resolved_tables": tables_output.name,
            "unresolved_candidates": unresolved_output.name,
            **(
                {"selected_item_targets": selected_output.name}
                if selected_rows_path is not None
                else {}
            ),
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifacts = [tables_output, unresolved_output]
    if selected_rows_path is not None:
        artifacts.append(selected_output)
    artifacts.append(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in artifacts),
        encoding="ascii",
    )
    print(
        f"orion-xac-offsets stage=complete tables={len(final_bindings)} rows={total_rows} "
        f"unique={len(final_bindings) - len(unresolved)} unresolved={len(unresolved)} "
        "checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--selected-rows", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    try:
        report = run(
            args.atlas,
            args.bindings,
            args.candidates,
            args.selected_rows,
            args.output,
            args.jobs,
        )
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-xac-offsets error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
