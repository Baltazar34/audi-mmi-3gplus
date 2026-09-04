#!/usr/bin/env python3
"""Infer observed payload cursor branches per static XAC descriptor class."""

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


def worker(job: tuple[list[tuple[str, list[int]]], str, int]) -> dict[str, object]:
    groups, firmware_path, table_offset = job
    classes: dict[str, Counter] = defaultdict(Counter)
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
                    continue
                static = str(parsed["static_descriptor_hex"])
                key = int(parsed["key"])
                class_key = f"key=0x{key:03x};static={static}"
                delta = following - int(parsed["structural_cursor"])
                classes[class_key]["pairs"] += 1
                classes[class_key][f"delta:{delta}"] += 1
                classes[class_key][f"flag:{int(parsed['effective_flags']):02x}"] += 1
        return {class_key: dict(counter) for class_key, counter in classes.items()}
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
    merged: dict[str, Counter] = defaultdict(Counter)
    for part in parts:
        for class_key, values in part.items():
            merged[class_key].update(values)
    classes = {}
    for class_key, values in sorted(merged.items()):
        pairs = int(values.pop("pairs", 0))
        deltas = Counter({key[6:]: value for key, value in values.items() if key.startswith("delta:")})
        flags = Counter({key[5:]: value for key, value in values.items() if key.startswith("flag:")})
        exact = deltas.get("0", 0)
        classes[class_key] = {
            "pairs": pairs,
            "exact_cursor_matches": exact,
            "exact_ratio": exact / pairs if pairs else 0.0,
            "delta_distribution": dict(sorted(deltas.items(), key=lambda item: (-item[1], int(item[0])))),
            "effective_flag_distribution": dict(sorted(flags.items(), key=lambda item: (-item[1], item[0]))),
        }
    report = {"selected": str(args.selected), "groups": len(groups), "jobs": jobs, "class_count": len(classes), "classes": classes}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    stable = sum(int(value["exact_ratio"] >= 0.95) for value in classes.values())
    print(json.dumps({"groups": len(groups), "jobs": jobs, "class_count": len(classes), "stable_classes": stable}, sort_keys=True))


if __name__ == "__main__":
    main()
