#!/usr/bin/env python3
"""Bind ordered Orion VidTable chunks to physical XAC VEKTORBLOCK records."""

from __future__ import annotations

import argparse
from bisect import bisect_right
from collections import Counter
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys


MARKER = b"VEKTORBLOCK     "
FLDB_ENTRY_SIZE = 36


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


def parse_fldb_directory(data: bytes | mmap.mmap, source_size: int) -> list[dict[str, object]]:
    """Parse the fixed-size FLDB directory stored after its padded header."""
    if len(data) < 28 or data[20:24] != b"FLDB":
        raise ValueError("input is not an FLDB database")
    header_size, file_count, entry_size = struct.unpack_from("<I8xII", data, 0)
    if entry_size != FLDB_ENTRY_SIZE:
        raise ValueError(f"unsupported FLDB entry size {entry_size}")
    directory_offset = header_size + 8
    directory_end = directory_offset + file_count * entry_size
    if directory_end > source_size:
        raise ValueError("FLDB directory exceeds input size")
    entries: list[dict[str, object]] = []
    for index in range(file_count):
        cursor = directory_offset + index * entry_size
        raw_name = bytes(data[cursor : cursor + 24]).split(b"\0", 1)[0]
        try:
            name = raw_name.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError(f"FLDB entry {index} has a non-ASCII name") from error
        crc32, offset, size = struct.unpack_from("<III", data, cursor + 24)
        if offset + size > source_size:
            raise ValueError(f"FLDB entry {name!r} exceeds input size")
        entries.append(
            {
                "entry_index": index,
                "name": name,
                "crc32": crc32,
                "offset": offset,
                "size": size,
            }
        )
    return entries


def owner_for_offset(
    entries: list[dict[str, object]], starts: list[int], offset: int
) -> dict[str, object] | None:
    index = bisect_right(starts, offset) - 1
    if index < 0:
        return None
    candidate = entries[index]
    start = int(candidate["offset"])
    if start <= offset < start + int(candidate["size"]):
        return candidate
    return None


def scan_fldb(path: Path, db_index: int) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Scan an entire FLDB physical image, including unowned continuation areas."""
    source_size = path.stat().st_size
    with path.open("rb") as source, mmap.mmap(
        source.fileno(), 0, access=mmap.ACCESS_READ
    ) as data:
        entries = parse_fldb_directory(data, source_size)
        nonempty = sorted(
            (entry for entry in entries if int(entry["size"]) > 0),
            key=lambda entry: int(entry["offset"]),
        )
        starts = [int(entry["offset"]) for entry in nonempty]
        vectors: list[dict[str, object]] = []
        cursor = 0
        while True:
            marker_offset = data.find(MARKER, cursor)
            if marker_offset < 0:
                break
            cursor = marker_offset + 1
            if marker_offset + 50 > source_size:
                continue
            owner = owner_for_offset(nonempty, starts, marker_offset)
            vector_size = struct.unpack_from(">I", data, marker_offset + 16)[0]
            vector_count = struct.unpack_from(">H", data, marker_offset + 48)[0]
            record: dict[str, object] = {
                "db_index": db_index,
                "db_path": str(path),
                "db_marker_index": len(vectors),
                "marker_offset": marker_offset,
                "marker_offset_hex": f"0x{marker_offset:x}",
                "vector_size_field": vector_size,
                "vector_count": vector_count,
                "owner_kind": "directory_entry" if owner else "unowned_physical_area",
                "owner_name": owner["name"] if owner else None,
                "owner_entry_index": owner["entry_index"] if owner else None,
                "owner_relative_offset": (
                    marker_offset - int(owner["offset"]) if owner else None
                ),
            }
            vectors.append(record)
        for index, vector in enumerate(vectors):
            marker_offset = int(vector["marker_offset"])
            upper_offsets = [source_size]
            if index + 1 < len(vectors):
                upper_offsets.append(int(vectors[index + 1]["marker_offset"]))
            owner_index = vector["owner_entry_index"]
            if owner_index is not None:
                owner = entries[int(owner_index)]
                upper_offsets.append(int(owner["offset"]) + int(owner["size"]))
            vector["physical_upper_bound_distance"] = min(upper_offsets) - marker_offset
    return entries, vectors


def subsequence_bounds(
    needle: list[int], haystack: list[int]
) -> tuple[list[int], list[int]]:
    """Return greedy earliest/latest embeddings, proving whether each match is forced."""
    earliest: list[int] = []
    cursor = 0
    for value in needle:
        while cursor < len(haystack) and haystack[cursor] != value:
            cursor += 1
        if cursor == len(haystack):
            raise ValueError("VidTable count sequence is not an XAC vector subsequence")
        earliest.append(cursor)
        cursor += 1

    latest = [0] * len(needle)
    cursor = len(haystack) - 1
    for index in range(len(needle) - 1, -1, -1):
        value = needle[index]
        while cursor >= 0 and haystack[cursor] != value:
            cursor -= 1
        if cursor < 0:
            raise ValueError("reverse XAC vector subsequence search failed")
        latest[index] = cursor
        cursor -= 1
    return earliest, latest


def run(tables_path: Path, db_paths: list[Path], output: Path) -> dict[str, object]:
    if not db_paths:
        raise ValueError("at least one --xac-db is required")
    tables = read_jsonl(tables_path)
    if not tables:
        raise ValueError("VidTable input is empty")
    print(
        f"orion-xac-bind stage=start vidtables={len(tables)} dbs={len(db_paths)}",
        file=sys.stderr,
        flush=True,
    )
    all_entries: list[dict[str, object]] = []
    vectors: list[dict[str, object]] = []
    for db_index, db_path in enumerate(db_paths):
        entries, scanned = scan_fldb(db_path, db_index)
        for entry in entries:
            entry.update({"db_index": db_index, "db_path": str(db_path)})
        for vector in scanned:
            vector["global_marker_index"] = len(vectors)
            vectors.append(vector)
        all_entries.extend(entries)
        print(
            f"orion-xac-bind stage=db-scanned db={db_index + 1}/{len(db_paths)} "
            f"entries={len(entries)} markers={len(scanned)}",
            file=sys.stderr,
            flush=True,
        )

    table_counts = [int(table["row_count"]) for table in tables]
    vector_counts = [int(vector["vector_count"]) for vector in vectors]
    earliest, latest = subsequence_bounds(table_counts, vector_counts)
    matched_indices = set(earliest)
    bindings: list[dict[str, object]] = []
    ambiguous_candidates: list[dict[str, object]] = []
    for table_index, marker_index in enumerate(earliest):
        table = tables[table_index]
        vector = vectors[marker_index]
        latest_index = latest[table_index]
        record = {
            "vidtable_index": table_index,
            "vidtable_block_offset": int(table["block_offset"]),
            "vidtable_block_offset_hex": table["block_offset_hex"],
            "vidtable_chunk_index": int(table["chunk_index"]),
            "row_count": int(table["row_count"]),
            "xac_offset_min": table["xac_offset_min"],
            "xac_offset_max": table["xac_offset_max"],
            **vector,
            "match_forced_by_count_order": marker_index == latest_index,
            "latest_candidate_global_marker_index": latest_index,
            "candidate_span_markers": latest_index - marker_index,
            "xac_max_minus_vector_size_field": (
                int(table["xac_offset_max"]) - int(vector["vector_size_field"])
                if table["xac_offset_max"] is not None
                else None
            ),
        }
        bindings.append(record)
        if marker_index != latest_index:
            for candidate_index in range(marker_index, latest_index + 1):
                candidate = vectors[candidate_index]
                if int(candidate["vector_count"]) != int(table["row_count"]):
                    continue
                ambiguous_candidates.append(
                    {
                        "vidtable_index": table_index,
                        "row_count": int(table["row_count"]),
                        "candidate_global_marker_index": candidate_index,
                        "selected_by_earliest_embedding": candidate_index == marker_index,
                        **candidate,
                    }
                )

    unmatched = [
        vector for index, vector in enumerate(vectors) if index not in matched_indices
    ]
    forced = sum(bool(row["match_forced_by_count_order"]) for row in bindings)
    relation_counts = Counter()
    for row in bindings:
        difference = row["xac_max_minus_vector_size_field"]
        relation_counts[
            "max_below_size" if difference < 0 else "max_equals_size" if difference == 0 else "max_above_size"
        ] += 1
    owner_counts = Counter(str(row["owner_kind"]) for row in bindings)
    per_db = Counter(int(row["db_index"]) for row in bindings)
    checks = {
        "all_vidtables_bound_in_order": len(bindings) == len(tables),
        "all_bound_counts_equal": all(
            int(row["row_count"]) == int(row["vector_count"]) for row in bindings
        ),
        "binding_indices_strictly_increase": all(
            left < right for left, right in zip(earliest, earliest[1:])
        ),
        "all_db_markers_accounted_for": len(bindings) + len(unmatched) == len(vectors),
        "all_offsets_fit_conservative_physical_bound": all(
            row["xac_offset_max"] is None
            or int(row["xac_offset_max"]) < int(row["physical_upper_bound_distance"])
            for row in bindings
        ),
    }
    if not all(checks.values()):
        raise ValueError(f"XAC binding checks failed: {checks}")

    output.mkdir(parents=True, exist_ok=True)
    bindings_path = output / "bindings.jsonl"
    unmatched_path = output / "unmatched_xac_vectors.jsonl"
    directory_path = output / "fldb_directory.jsonl"
    candidates_path = output / "ambiguous_binding_candidates.jsonl"
    report_path = output / "report.json"
    write_jsonl(bindings_path, bindings)
    write_jsonl(unmatched_path, unmatched)
    write_jsonl(directory_path, all_entries)
    write_jsonl(candidates_path, ambiguous_candidates)
    differences = [int(row["xac_max_minus_vector_size_field"]) for row in bindings]
    report = {
        "schema_version": 1,
        "status": "complete",
        "tables": str(tables_path),
        "xac_databases": [str(path) for path in db_paths],
        "vidtable_chunks": len(tables),
        "physical_vector_blocks": len(vectors),
        "bound_vector_blocks": len(bindings),
        "extra_xac_vector_blocks": len(unmatched),
        "forced_count_order_bindings": forced,
        "nonforced_count_order_bindings": len(bindings) - forced,
        "ambiguous_candidate_rows": len(ambiguous_candidates),
        "bound_by_db_index": {str(key): value for key, value in sorted(per_db.items())},
        "bound_owner_kinds": dict(sorted(owner_counts.items())),
        "xac_offset_max_vs_size_field": dict(sorted(relation_counts.items())),
        "xac_max_minus_size_field_range": [min(differences), max(differences)],
        "checks": checks,
        "interpretation": (
            "Every VidTable chunk is embedded in order in the physical VEKTORBLOCK count "
            "sequence. XacVectorOffsets are therefore local to the associated vector-block "
            "namespace; the exact byte-base convention inside that block is not asserted here."
        ),
        "artifacts": {
            "bindings": bindings_path.name,
            "unmatched_xac_vectors": unmatched_path.name,
            "fldb_directory": directory_path.name,
            "ambiguous_binding_candidates": candidates_path.name,
        },
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_paths = (
        bindings_path,
        unmatched_path,
        directory_path,
        candidates_path,
        report_path,
    )
    (output / "CHECKSUMS.sha256").write_text(
        "".join(f"{sha256(path)}  {path.name}\n" for path in artifact_paths),
        encoding="ascii",
    )
    print(
        f"orion-xac-bind stage=complete bound={len(bindings)} physical={len(vectors)} "
        f"forced={forced} checks=all-pass",
        file=sys.stderr,
        flush=True,
    )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tables", type=Path, required=True)
    parser.add_argument("--xac-db", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = run(args.tables, args.xac_db, args.output)
    except (KeyError, OSError, TypeError, ValueError) as error:
        print(f"orion-xac-bind error={error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
