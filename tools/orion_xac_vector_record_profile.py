#!/usr/bin/env python3
"""Profile firmware-defined 0xc0 XAC vector record headers in parallel."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path
import struct


def read_rows(path: Path) -> list[dict[str, object]]:
    with path.open(encoding="utf-8") as source:
        return [json.loads(line) for line in source]


def chunks(rows: list[dict[str, object]], count: int) -> list[list[dict[str, object]]]:
    size = max(1, (len(rows) + count - 1) // count)
    return [rows[start : start + size] for start in range(0, len(rows), size)]


def profile_chunk(rows: list[dict[str, object]]) -> dict[str, object]:
    files: dict[str, object] = {}
    maps: dict[str, mmap.mmap] = {}
    first = Counter()
    flags = Counter()
    keys = Counter()
    classes = Counter()
    failures = Counter()
    try:
        for row in rows:
            name = str(row["xac_db_path"])
            if name not in maps:
                handle = Path(name).open("rb")
                files[name] = handle
                maps[name] = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            data = maps[name]
            offset = int(row["xac_target_absolute_offset"])
            raw = data[offset : offset + 8]
            if len(raw) < 4:
                failures["truncated_header"] += 1
                continue
            b0, b1, b2, b3 = raw[:4]
            if b0 & 0xC0 != 0xC0:
                failures["invalid_signature"] += 1
                continue
            key = ((b2 & 7) << 8) | b3
            first[f"0x{b0:02x}"] += 1
            flags[f"0x{b2:02x}"] += 1
            keys[f"0x{key:03x}"] += 1
            classes[
                f"sig=0x{b0 & 0xc0:02x};type=0x{b0 & 0x3f:02x};"
                f"backref={(b2 & 8) != 0};extra={(b2 & 0x40) != 0};key=0x{key:03x}"
            ] += 1
        return {
            "records": sum(first.values()),
            "first_byte": dict(first),
            "flag_byte": dict(flags),
            "key": dict(keys),
            "class": dict(classes),
            "failures": dict(failures),
        }
    finally:
        for data in maps.values():
            data.close()
        for handle in files.values():
            handle.close()


def merge(parts: list[dict[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {"records": 0}
    for name in ("first_byte", "flag_byte", "key", "class", "failures"):
        counter = Counter()
        for part in parts:
            counter.update(part[name])
        result[name] = dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))
    result["records"] = sum(int(part["records"]) for part in parts)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selected", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    rows = read_rows(args.selected)
    jobs = max(1, min(args.jobs, len(rows) or 1))
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(profile_chunk, chunks(rows, jobs)))
    report = merge(parts)
    report["selected_rows"] = len(rows)
    report["jobs"] = jobs
    report["source"] = str(args.selected)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"records": report["records"], "failures": report["failures"], "jobs": jobs}, sort_keys=True))


if __name__ == "__main__":
    main()
