#!/usr/bin/env python3
"""Validate structural XAC cursors against ordered physical targets."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_xac_vector_record_layout import parse_record, rows_by_group


def worker(job: tuple[list[tuple[str, list[int]]], str, int]) -> dict[str, object]:
    groups, firmware_path, table_offset = job
    result = Counter()
    distance = Counter()
    handles: dict[str, object] = {}
    maps: dict[str, mmap.mmap] = {}
    firmware_handle = Path(firmware_path).open("rb")
    firmware = mmap.mmap(firmware_handle.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        for path, offsets in groups:
            if path not in maps:
                handle = Path(path).open("rb")
                handles[path] = handle
                maps[path] = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            data = maps[path]
            for current, following in zip(offsets, offsets[1:]):
                try:
                    parsed = parse_record(data, current, firmware, table_offset)
                except (IndexError, ValueError):
                    result["parse_failures"] += 1
                    continue
                cursor = int(parsed["structural_cursor"])
                delta = following - cursor
                distance[delta] += 1
                if delta == 0:
                    result["cursor_equals_next"] += 1
                elif delta > 0:
                    result["cursor_before_next"] += 1
                else:
                    result["cursor_after_next"] += 1
                result["pairs"] += 1
        return {"summary": dict(result), "distance": dict(distance)}
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
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    groups = rows_by_group(args.selected)
    table_offset = args.type_table_va - args.va_base
    jobs = max(1, min(args.jobs, len(groups) or 1))
    size = max(1, (len(groups) + jobs - 1) // jobs)
    batches = [(groups[i : i + size], str(args.firmware), table_offset) for i in range(0, len(groups), size)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(worker, batches))
    summary = Counter()
    distance = Counter()
    for part in parts:
        summary.update(part["summary"])
        distance.update(part["distance"])
    report = {
        "selected": str(args.selected),
        "groups": len(groups),
        "jobs": jobs,
        "summary": dict(summary),
        "cursor_minus_next_distance": dict(sorted(distance.items(), key=lambda item: (-item[1], int(item[0])))),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"groups": len(groups), "jobs": jobs, **dict(summary)}, sort_keys=True))


if __name__ == "__main__":
    main()
