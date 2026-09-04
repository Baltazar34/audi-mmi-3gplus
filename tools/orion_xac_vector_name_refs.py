#!/usr/bin/env python3
"""Extract XAC name references using NavCore's get_names_of_vector grammar."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_xac_vector_record_layout import parse_record


def read_groups(path: Path) -> list[tuple[str, list[dict[str, object]]]]:
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    with path.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            groups[str(row["xac_db_path"])].append(row)
    return list(groups.items())


def decode_name_refs(data: mmap.mmap, cursor: int, limit: int) -> tuple[list[int], bool]:
    """Decode packed 14-bit IDs; bit 6 continues, 0x3fff is the sentinel."""
    values: list[int] = []
    for _ in range(limit):
        if cursor + 2 > len(data):
            raise ValueError("truncated name-reference list")
        first, second = data[cursor], data[cursor + 1]
        cursor += 2
        value = ((first & 0x3F) << 8) | second
        if value != 0x3FFF:
            values.append(value)
        if not (first & 0x40):
            return values, True
    return values, False


def worker(job: tuple[list[tuple[str, list[dict[str, object]]]], str, int, int]) -> dict[str, object]:
    groups, firmware_path, table_offset, limit = job
    summaries: Counter[str] = Counter()
    refs: Counter[int] = Counter()
    failures: Counter[str] = Counter()
    records = 0
    handles: dict[str, object] = {}
    maps: dict[str, mmap.mmap] = {}
    firmware_handle = Path(firmware_path).open("rb")
    firmware = mmap.mmap(firmware_handle.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        for path, rows in groups:
            if path not in maps:
                handle = Path(path).open("rb")
                handles[path] = handle
                maps[path] = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            data = maps[path]
            for row in rows:
                try:
                    parsed = parse_record(data, int(row["xac_target_absolute_offset"]), firmware, table_offset)
                    if not (int(parsed["descriptor0"]) & 0x20):
                        continue
                    values, terminated = decode_name_refs(data, int(parsed["name_cursor"]), limit)
                except (IndexError, ValueError) as error:
                    failures[str(error)] += 1
                    continue
                class_key = f"key=0x{int(parsed['key']):03x};static={parsed['static_descriptor_hex']}"
                summaries[f"{class_key};records"] += 1
                summaries[f"{class_key};refs"] += len(values)
                summaries[f"{class_key};unterminated"] += int(not terminated)
                refs.update(values)
                records += 1
        return {"records": records, "summary": dict(summaries), "refs": dict(refs), "failures": dict(failures)}
    finally:
        for data in maps.values():
            data.close()
        for handle in handles.values():
            handle.close()
        firmware.close()
        firmware_handle.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selected", type=Path, required=True)
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--type-table-va", type=lambda value: int(value, 0), default=0x085B4FE8)
    parser.add_argument("--va-base", type=lambda value: int(value, 0), default=0x08040000)
    parser.add_argument("--max-refs", type=int, default=64)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    groups = read_groups(args.selected)
    jobs = max(1, min(args.jobs, len(groups) or 1))
    size = max(1, (len(groups) + jobs - 1) // jobs)
    table_offset = args.type_table_va - args.va_base
    batches = [(groups[i : i + size], str(args.firmware), table_offset, args.max_refs) for i in range(0, len(groups), size)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(worker, batches))
    summary: Counter[str] = Counter()
    refs: Counter[int] = Counter()
    failures: Counter[str] = Counter()
    records = 0
    for part in parts:
        records += int(part["records"])
        summary.update(part["summary"])
        refs.update({int(key): value for key, value in part["refs"].items()})
        failures.update(part["failures"])
    report = {
        "selected": str(args.selected),
        "records_with_name_flag": records,
        "jobs": jobs,
        "failures": dict(failures),
        "class_summary": dict(sorted(summary.items())),
        "referenced_name_ids": {f"0x{key:04x}": value for key, value in sorted(refs.items())},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"records_with_name_flag": records, "distinct_name_ids": len(refs), "failures": dict(failures), "jobs": jobs}, sort_keys=True))


if __name__ == "__main__":
    main()
