#!/usr/bin/env python3
"""Decode the firmware-defined structural layout of 0xc0 XAC records."""

from __future__ import annotations

import argparse
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path


VA_BASE = 0x08040000
DEFAULT_TYPE_TABLE_VA = 0x085B4FE8


def rows_by_group(path: Path) -> list[tuple[str, list[int]]]:
    groups: dict[tuple[str, int, str], set[int]] = {}
    with path.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            key = (str(row["xac_db_path"]), int(row["xac_marker_offset"]), str(row["xac_owner_name"]))
            groups.setdefault(key, set()).add(int(row["xac_target_absolute_offset"]))
    return [(key[0], sorted(offsets)) for key, offsets in groups.items()]


def parse_record(data: mmap.mmap, offset: int, type_table: mmap.mmap, table_offset: int) -> dict[str, int | bool | str]:
    raw = data[offset : offset + 4]
    if len(raw) < 4:
        raise ValueError("truncated record header")
    b0, _b1, b2, b3 = raw
    if b0 & 0xC0 != 0xC0:
        raise ValueError("invalid 0xc0 signature")
    cursor = offset + 4
    effective_b2, effective_b3 = b2, b3
    backref = bool(b2 & 0x08)
    if backref:
        distance = (((b2 & 7) << 8) | b3) * 2 + 2
        prior = cursor - distance
        if prior < 0:
            raise ValueError("back-reference precedes database")
        prior_raw = data[prior : prior + 2]
        if len(prior_raw) < 2:
            raise ValueError("truncated back-reference header")
        effective_b2, effective_b3 = prior_raw
        cursor = prior + 2
    if effective_b2 & 0x40:
        cursor += 2
    key = ((effective_b2 & 7) << 8) | effective_b3
    descriptor_offset = table_offset + 0x1C + key * 4
    descriptor = type_table[descriptor_offset : descriptor_offset + 4]
    if len(descriptor) < 4:
        raise ValueError("type-table descriptor is out of range")
    static_descriptor0, _descriptor1, static_descriptor2, _descriptor3 = descriptor
    descriptor0 = static_descriptor0
    descriptor2 = static_descriptor2
    dynamic0 = bool(descriptor0 & 0x80)
    dynamic2 = bool(descriptor2 & 0x80)
    if dynamic0:
        if cursor + 2 > len(data):
            raise ValueError("dynamic descriptor field is truncated")
        descriptor0 = data[cursor]
        cursor += 2
    if dynamic2:
        cursor += 2
    if descriptor0 & 0x40:
        cursor += 4
    if descriptor0 & 0x10:
        cursor += 4
    return {
        "record_offset": offset,
        "record_type": b0 & 0x3F,
        "header_flags": b2,
        "effective_flags": effective_b2,
        "key": key,
        "descriptor0": descriptor0,
        "descriptor2": descriptor2,
        "static_descriptor_hex": descriptor.hex(),
        "static_descriptor0": static_descriptor0,
        "static_descriptor2": static_descriptor2,
        "dynamic_descriptor0": dynamic0,
        "dynamic_descriptor2": dynamic2,
        "backref": backref,
        "name_cursor": cursor,
        "structural_cursor": cursor,
    }


def worker(job: tuple[list[tuple[str, list[int]]], str, int]) -> dict[str, object]:
    groups, firmware_path, table_offset = job
    records: list[dict[str, int | bool | str]] = []
    failures: dict[str, int] = {}
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
                    records.append(parse_record(data, offset, firmware, table_offset))
                except (IndexError, ValueError) as error:
                    failures[str(error)] = failures.get(str(error), 0) + 1
        return {"records": records, "failures": failures}
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
    parser.add_argument("--type-table-va", type=lambda value: int(value, 0), default=DEFAULT_TYPE_TABLE_VA)
    parser.add_argument("--va-base", type=lambda value: int(value, 0), default=VA_BASE)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    groups = rows_by_group(args.selected)
    table_offset = args.type_table_va - args.va_base
    jobs = max(1, min(args.jobs, len(groups) or 1))
    size = max(1, (len(groups) + jobs - 1) // jobs)
    batches = [(groups[i : i + size], str(args.firmware), table_offset) for i in range(0, len(groups), size)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(worker, batches))
    records = [record for part in parts for record in part["records"]]
    failures: dict[str, int] = {}
    for part in parts:
        for reason, count in part["failures"].items():
            failures[reason] = failures.get(reason, 0) + count
    report = {
        "selected": str(args.selected),
        "records": len(records),
        "groups": len(groups),
        "jobs": jobs,
        "va_base": hex(args.va_base),
        "type_table_va": hex(args.type_table_va),
        "type_table_file_offset": hex(table_offset),
        "failures": failures,
        "records_layout": records,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"records": len(records), "groups": len(groups), "failures": failures, "jobs": jobs}, sort_keys=True))


if __name__ == "__main__":
    main()
