#!/usr/bin/env python3
"""Profile runtime XAC payload branches by static and dynamic descriptors."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_xac_vector_record_layout import parse_record, rows_by_group


def worker(job: tuple[list[tuple[str, list[int]]], str, int, int]) -> dict[str, object]:
    groups, firmware_path, table_offset, sample_bytes = job
    counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = defaultdict(list)
    failures: Counter[str] = Counter()
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
            for offset in offsets:
                try:
                    parsed = parse_record(data, offset, firmware, table_offset)
                except (IndexError, ValueError) as error:
                    failures[str(error)] += 1
                    continue
                branch = (
                    f"key=0x{int(parsed['key']):03x};static={parsed['static_descriptor_hex']}"
                    f";header=0x{int(parsed['header_flags']):02x};effective=0x{int(parsed['descriptor0']):02x}/0x{int(parsed['descriptor2']):02x}"
                )
                counts[branch] += 1
                if len(samples[branch]) < 4:
                    start = int(parsed["record_offset"]) + 4
                    samples[branch].append(data[start : start + sample_bytes].hex())
        return {"counts": dict(counts), "samples": dict(samples), "failures": dict(failures)}
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
    parser.add_argument("--sample-bytes", type=int, default=24)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    groups = rows_by_group(args.selected)
    table_offset = args.type_table_va - args.va_base
    jobs = max(1, min(args.jobs, len(groups) or 1))
    size = max(1, (len(groups) + jobs - 1) // jobs)
    batches = [(groups[i : i + size], str(args.firmware), table_offset, args.sample_bytes) for i in range(0, len(groups), size)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(worker, batches))
    counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = defaultdict(list)
    failures: Counter[str] = Counter()
    for part in parts:
        counts.update(part["counts"])
        failures.update(part["failures"])
        for branch, values in part["samples"].items():
            samples[branch].extend(values)
    report = {"selected": str(args.selected), "firmware": str(args.firmware), "jobs": jobs, "records": sum(counts.values()), "branch_count": len(counts), "failures": dict(failures), "branches": {branch: {"count": counts[branch], "samples": samples[branch][:4]} for branch in sorted(counts)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"records": report["records"], "branch_count": report["branch_count"], "failures": report["failures"], "jobs": jobs}, sort_keys=True))


if __name__ == "__main__":
    main()
