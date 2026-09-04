#!/usr/bin/env python3
"""orion_index_block_profile.py — profil `INDEX` i `REVISION` blokova.

`INDEX` blokovi postoje samo u nultom delu svake ATLAS baze, odmah iza
`HEADER`-a, pa ih raniji rad nad PSD3 (deo 2) nije mogao videti.

Posmatrana gramatika INDEX bloka:

    +0x00  u8 len + "INDEX", popuna 0xcc
    +0x10  u32 velicina bloka
    +0x14  u8[4] format verzija
    +0x18  u8 nivo, u8 ?, u16 ?
    +0x1c  u32 ?
    +0x20  niz zapisa od 8 B
    kraj   terminator 16 B

Zapis se cita kao `u64` little-endian; donji bajt je mala vrednost
(posmatrano 0x17..0x1c), a gornja 32 bita rastu kroz blok. Skripta meri
tu monotonost umesto da je pretpostavi i ne imenuje polja.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

TERMINATOR = bytes.fromhex("0123456789abcdeffedcba9876543210")
RECORD = 8
RECORD_START = 0x20


def profile(path: Path) -> dict[str, object]:
    file_size = path.stat().st_size
    offset = 0
    blocks = Counter()
    index_blocks = 0
    record_total = 0
    low_bytes: Counter[int] = Counter()
    header_18: Counter[str] = Counter()
    sizes: Counter[int] = Counter()
    ascending_blocks = 0
    leftover: Counter[int] = Counter()
    first_key = None
    last_key = None
    container_seen = 0

    with path.open("rb") as source:
        while True:
            source.seek(offset)
            head = source.read(0x24)
            if len(head) < 0x24:
                break
            name_length = head[0]
            if name_length == 0 or name_length > 0x0F:
                break
            name = head[1:1 + name_length].decode("ascii", "replace")
            block_size = struct.unpack_from("<I", head, 0x10)[0]
            if block_size < 0x20 or offset + block_size > file_size:
                break
            blocks[name] += 1
            if name == "CONTAINER":
                container_seen += 1
                if container_seen > 4:
                    break  # indeksna zona je iza HEADER-a, pre podataka
            if name == "INDEX":
                index_blocks += 1
                sizes[block_size] += 1
                header_18["+".join(f"{b:02x}" for b in head[0x18:0x1C])] += 1
                source.seek(offset)
                block = source.read(block_size)
                body = block[RECORD_START:block_size - len(TERMINATOR)]
                count = len(body) // RECORD
                leftover[len(body) % RECORD] += 1
                keys = [struct.unpack_from("<Q", body, i * RECORD)[0]
                        for i in range(count)]
                record_total += count
                for key in keys:
                    low_bytes[key & 0xFF] += 1
                if all(keys[i] >> 8 <= keys[i + 1] >> 8 for i in range(len(keys) - 1)):
                    ascending_blocks += 1
                if keys:
                    if first_key is None:
                        first_key = keys[0]
                    last_key = keys[-1]
            offset += block_size

    return {
        "file": str(path),
        "file_size": file_size,
        "blocks_before_data": dict(blocks.most_common()),
        "index_block_count": index_blocks,
        "index_block_sizes": dict(sizes.most_common()),
        "index_record_total": record_total,
        "record_size": RECORD,
        "record_low_byte_values": dict(sorted(low_bytes.items())),
        "header_0x18_values": dict(header_18.most_common(10)),
        "blocks_with_ascending_keys": ascending_blocks,
        "trailing_bytes_after_records": dict(sorted(leftover.items())),
        "first_key": f"0x{first_key:016x}" if first_key else None,
        "last_key": f"0x{last_key:016x}" if last_key else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    reports = []
    for path in args.atlas:
        report = profile(path)
        reports.append(report)
        print(f"{path.parent.name:<10} INDEX blokova={report['index_block_count']:>5}  "
              f"zapisa={report['index_record_total']:>9,}  "
              f"rastucih={report['blocks_with_ascending_keys']:>5}  "
              f"ostatak={report['trailing_bytes_after_records']}")
    (args.output / "report.json").write_text(
        json.dumps({"files": reports}, indent=2, ensure_ascii=False))
    lines = []
    for item in sorted(args.output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
    (args.output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
