#!/usr/bin/env python3
"""Collect bounded payload samples per XAC descriptor class in parallel."""

from __future__ import annotations

import argparse
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_xac_vector_record_layout import parse_record, rows_by_group


def worker(job: tuple[list[tuple[str, list[int]]], str, int, int, int]) -> dict[str, object]:
    groups, firmware_path, table_offset, sample_limit, payload_bytes = job
    samples: dict[str, list[dict[str, object]]] = defaultdict(list)
    counts: dict[str, int] = defaultdict(int)
    failures: dict[str, int] = defaultdict(int)
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
                class_key = (
                    f"key=0x{int(parsed['key']):03x};static={parsed['static_descriptor_hex']}"
                )
                counts[class_key] += 1
                if len(samples[class_key]) < sample_limit:
                    start = int(parsed["record_offset"])
                    end = min(len(data), start + 4 + payload_bytes)
                    samples[class_key].append({
                        "offset": start,
                        "record_type": parsed["record_type"],
                        "header_flags": parsed["header_flags"],
                        "effective_descriptor0": parsed["descriptor0"],
                        "effective_descriptor2": parsed["descriptor2"],
                        "static_descriptor_hex": parsed["static_descriptor_hex"],
                        "payload_after_header_hex": data[start + 4 : end].hex(),
                    })
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
    parser.add_argument("--sample-limit", type=int, default=8)
    parser.add_argument("--payload-bytes", type=int, default=24)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    groups = rows_by_group(args.selected)
    table_offset = args.type_table_va - args.va_base
    jobs = max(1, min(args.jobs, len(groups) or 1))
    size = max(1, (len(groups) + jobs - 1) // jobs)
    batches = [(groups[i : i + size], str(args.firmware), table_offset, args.sample_limit, args.payload_bytes) for i in range(0, len(groups), size)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(worker, batches))
    counts: dict[str, int] = defaultdict(int)
    samples: dict[str, list[dict[str, object]]] = defaultdict(list)
    failures: dict[str, int] = defaultdict(int)
    for part in parts:
        for key, count in part["counts"].items():
            counts[key] += count
        for key, rows in part["samples"].items():
            samples[key].extend(rows)
        for reason, count in part["failures"].items():
            failures[reason] += count
    for key in samples:
        samples[key] = samples[key][: args.sample_limit]
    report = {"selected": str(args.selected), "firmware": str(args.firmware), "jobs": jobs, "records": sum(counts.values()), "class_count": len(counts), "failures": dict(failures), "classes": {key: {"count": counts[key], "samples": samples[key]} for key in sorted(counts)}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"records": report["records"], "class_count": report["class_count"], "failures": report["failures"], "jobs": jobs}, sort_keys=True))


if __name__ == "__main__":
    main()
