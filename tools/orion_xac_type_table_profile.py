#!/usr/bin/env python3
"""Export the active NavCore XAC descriptor table and observed key counts."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path


VA_BASE = 0x08040000
TYPE_TABLE_VA = 0x085B4FE8


def observed_keys(selected: Path) -> Counter[int]:
    counts: Counter[int] = Counter()
    with selected.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            prefix = bytes.fromhex(str(row["xac_target_prefix_hex"]))
            if len(prefix) >= 4 and prefix[0] & 0xC0 == 0xC0:
                counts[((prefix[2] & 7) << 8) | prefix[3]] += 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--firmware", type=Path, required=True)
    parser.add_argument("--selected", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--type-table-va", type=lambda value: int(value, 0), default=TYPE_TABLE_VA)
    parser.add_argument("--va-base", type=lambda value: int(value, 0), default=VA_BASE)
    args = parser.parse_args()
    data = args.firmware.read_bytes()
    table_offset = args.type_table_va - args.va_base
    counts = observed_keys(args.selected)
    entries = []
    for key in range(0x800):
        offset = table_offset + 0x1C + key * 4
        descriptor = data[offset : offset + 4]
        if len(descriptor) < 4:
            raise ValueError(f"descriptor entry {key:#x} is out of range")
        entries.append({
            "key": key,
            "key_hex": f"0x{key:03x}",
            "descriptor_hex": descriptor.hex(),
            "descriptor0": descriptor[0],
            "descriptor1": descriptor[1],
            "descriptor2": descriptor[2],
            "descriptor3": descriptor[3],
            "observed_rows": counts.get(key, 0),
        })
    report = {
        "firmware": str(args.firmware),
        "type_table_va": hex(args.type_table_va),
        "type_table_file_offset": hex(table_offset),
        "entry_count": len(entries),
        "observed_rows": sum(counts.values()),
        "entries": entries,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"entry_count": len(entries), "observed_rows": sum(counts.values())}, sort_keys=True))


if __name__ == "__main__":
    main()
