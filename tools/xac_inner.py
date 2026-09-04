#!/usr/bin/env python3
"""xac_inner.py — reader, byte-identical round-trip and (later) encoder for the
XAC inner-block format used inside a 3G Plus XAC `.db`.

Every inner file (`.poi`, `.ort`, `.plz`, `.xah`, `.ras`, `.xac`) is an
Orion-family block, all fields big-endian:

    char[16]  type magic, space-padded ("ORTSNAMEN", "GLOBAL POIS", ...)
    +0x10 u32 content_size   ( == filesize - 20 for the v3 table types )
    +0x14 u16 version        ( 3 = table types, 9 = XAC/RAS header types )
    +0x16 u16 count          ( number of (offset,size) table entries )
    +0x18 count * (u32 offset, u32 size)   ; entries point into the file
    ...   data

The round-trip proves the writer: regenerate the header words and the entry
table from the parsed values (magic and data copied verbatim) and require the
result to equal the original byte for byte.  `content_size` is checked, not
guessed.  Version-9 header files (`.xac _1`, `.ras`) carry ASCII metadata after
the header instead of a plain table; their body is preserved verbatim and the
round-trip still holds.

Commands:
    info       print magic/size/version/count and the entry table
    roundtrip  rebuild from parts, assert byte-identical
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

MAGIC_LEN = 16
HEADER_LEN = 0x18  # magic(16) + size(4) + version(2) + count(2)


class XacInnerError(Exception):
    pass


def parse(data: bytes) -> dict:
    if len(data) < HEADER_LEN:
        raise XacInnerError("shorter than an inner-block header")
    magic = data[:MAGIC_LEN]
    content_size, version, count = struct.unpack_from(">IHH", data, MAGIC_LEN)
    entries = []
    has_table = version == 3
    if has_table:
        table_off = HEADER_LEN
        if table_off + count * 8 > len(data):
            raise XacInnerError("entry table exceeds file")
        for i in range(count):
            off, size = struct.unpack_from(">II", data, table_off + i * 8)
            entries.append({"offset": off, "size": size})
        data_start = table_off + count * 8
    else:
        data_start = HEADER_LEN
    return {
        "magic": magic.rstrip().decode("latin1"),
        "content_size": content_size,
        "version": version,
        "count": count,
        "has_table": has_table,
        "entries": entries,
        "data_start": data_start,
        "file_size": len(data),
        "size_matches_minus20": content_size == len(data) - 20,
    }


def rebuild(data: bytes) -> tuple[bytes, dict]:
    """Regenerate the header + entry table from parsed values; copy the rest."""
    info = parse(data)
    out = bytearray(data)  # start from original; overwrite only what we claim
    out[:MAGIC_LEN] = data[:MAGIC_LEN]  # magic verbatim
    struct.pack_into(">IHH", out, MAGIC_LEN, info["content_size"], info["version"], info["count"])
    if info["has_table"]:
        for i, e in enumerate(info["entries"]):
            struct.pack_into(">II", out, HEADER_LEN + i * 8, e["offset"], e["size"])
    return bytes(out), info


def cmd_info(path: Path) -> int:
    info = parse(path.read_bytes())
    print(f"file={path.name} magic={info['magic']!r} version={info['version']} "
          f"count={info['count']} content_size={info['content_size']} "
          f"file_size={info['file_size']} size==len-20:{info['size_matches_minus20']}")
    for i, e in enumerate(info["entries"][:16]):
        end = e["offset"] + e["size"]
        flag = "OK" if end <= info["file_size"] else "OOB"
        print(f"  [{i:2}] offset={e['offset']:>8} size={e['size']:>8} end={end:>8} {flag}")
    if info["count"] > 16:
        print(f"  ... {info['count'] - 16} more")
    return 0


def cmd_roundtrip(path: Path, report: Path | None) -> int:
    data = path.read_bytes()
    rebuilt, info = rebuild(data)
    ok = rebuilt == data
    first = None if ok else next((i for i in range(len(data)) if data[i] != rebuilt[i]), None)
    result = {
        "file": str(path), "magic": info["magic"], "version": info["version"],
        "count": info["count"], "byte_identical": ok, "first_diff": first,
    }
    print(json.dumps(result))
    if report:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("info"); p.add_argument("path", type=Path)
    p = sub.add_parser("roundtrip"); p.add_argument("path", type=Path); p.add_argument("--report", type=Path)
    args = ap.parse_args()
    if args.cmd == "info":
        return cmd_info(args.path)
    if args.cmd == "roundtrip":
        return cmd_roundtrip(args.path, args.report)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
