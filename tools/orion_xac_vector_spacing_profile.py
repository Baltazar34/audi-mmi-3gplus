#!/usr/bin/env python3
"""Profile spacing between ordered XAC vector targets using parallel workers."""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
import json
import mmap
from pathlib import Path


def groups_from_jsonl(path: Path) -> list[tuple[str, list[int]]]:
    groups: dict[tuple[str, int, str], set[int]] = {}
    with path.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            key = (str(row["xac_db_path"]), int(row["xac_marker_offset"]), str(row["xac_owner_name"]))
            groups.setdefault(key, set()).add(int(row["xac_target_absolute_offset"]))
    return [(key[0], sorted(offsets)) for key, offsets in groups.items()]


def worker(groups: list[tuple[str, list[int]]]) -> dict[str, object]:
    by_delta = Counter()
    by_class = Counter()
    pairs = 0
    handles: dict[str, object] = {}
    maps: dict[str, mmap.mmap] = {}
    try:
        for path, offsets in groups:
            if path not in maps:
                handle = Path(path).open("rb")
                handles[path] = handle
                maps[path] = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            data = maps[path]
            for current, following in zip(offsets, offsets[1:]):
                raw = data[current : current + 4]
                if len(raw) < 4 or raw[0] & 0xC0 != 0xC0:
                    continue
                delta = following - current
                key = ((raw[2] & 7) << 8) | raw[3]
                by_delta[delta] += 1
                by_class[f"flags=0x{raw[2]:02x};key=0x{key:03x};delta={delta}"] += 1
                pairs += 1
        return {"pairs": pairs, "delta": dict(by_delta), "class_delta": dict(by_class)}
    finally:
        for data in maps.values():
            data.close()
        for handle in handles.values():
            handle.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selected", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=8)
    args = parser.parse_args()
    groups = groups_from_jsonl(args.selected)
    jobs = max(1, min(args.jobs, len(groups) or 1))
    size = max(1, (len(groups) + jobs - 1) // jobs)
    batches = [groups[i : i + size] for i in range(0, len(groups), size)]
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        parts = list(pool.map(worker, batches))
    delta = Counter()
    class_delta = Counter()
    pairs = 0
    for part in parts:
        pairs += int(part["pairs"])
        delta.update(part["delta"])
        class_delta.update(part["class_delta"])
    report = {
        "selected": str(args.selected),
        "groups": len(groups),
        "jobs": jobs,
        "pairs": pairs,
        "delta": dict(sorted(delta.items(), key=lambda item: (-item[1], int(item[0])))),
        "class_delta": dict(sorted(class_delta.items(), key=lambda item: (-item[1], item[0]))),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"groups": len(groups), "pairs": pairs, "jobs": jobs}, sort_keys=True))


if __name__ == "__main__":
    main()
