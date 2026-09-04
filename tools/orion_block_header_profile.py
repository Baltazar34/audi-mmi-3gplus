#!/usr/bin/env python3
"""orion_block_header_profile.py — read-only profil ATLAS block headera.

Container sloj (stavka 3) je jedini deo formata koji do sada nije profilisan.
Blok header je 0x20 B pre chunk tabele:

    +0x00  u8 len + ime, popunjeno 0xcc/0xcb do 0x10
    +0x10  u32 velicina bloka (po njoj se seta lanac)
    +0x14  u32 verzija/flagovi
    +0x18  u32 kandidat za prostorni kljuc + nivo
    +0x1c  u32 konstanta tipa bloka
    +0x20  u8 chunk kind, u8 chunk count, pa (csize,usize) parovi

Skripta ne menja fajl. Ispisuje raspodele, proverava monotonost kljuca i
cuva NDJSON sa svim blokovima da bi writer imao dokazani ulaz.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path


def read_name(header: bytes) -> str | None:
    length = header[0]
    if length == 0 or length > 0x0F:
        return None
    raw = header[1:1 + length]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def iter_blocks(path: Path, limit: int):
    size = path.stat().st_size
    offset = 0
    index = 0
    with path.open("rb") as source:
        while limit == 0 or index < limit:
            source.seek(offset)
            header = source.read(0x40)
            if len(header) < 0x40:
                break
            name = read_name(header)
            block_size = struct.unpack_from("<I", header, 0x10)[0]
            if name is None or block_size < 0x20 or offset + block_size > size:
                break
            yield offset, name, block_size, header
            offset += block_size
            index += 1
    return


def profile(path: Path, limit: int, rows_path: Path | None) -> dict[str, object]:
    names: Counter[str] = Counter()
    version_words: Counter[int] = Counter()
    type_words: Counter[str] = Counter()
    tail_words: Counter[str] = Counter()
    chunk_kinds: Counter[int] = Counter()
    chunk_counts: Counter[int] = Counter()
    used_slots: Counter[int] = Counter()

    key_levels: Counter[int] = Counter()
    previous_key: int | None = None
    key_monotonic = True
    key_strictly_increasing = True
    key_min = None
    key_max = None
    level_by_name: dict[str, Counter[int]] = {}

    total = 0
    covered = 0
    rows = rows_path.open("w", encoding="utf-8") if rows_path else None
    try:
        for offset, name, block_size, header in iter_blocks(path, limit):
            total += 1
            covered += block_size
            names[name] += 1
            version = struct.unpack_from("<I", header, 0x14)[0]
            key_word = struct.unpack_from("<I", header, 0x18)[0]
            type_word = struct.unpack_from("<I", header, 0x1C)[0]
            version_words[version] += 1
            type_words[f"0x{type_word:08x}"] += 1
            tail_words[header[0x38:0x40].hex()] += 1

            level = key_word & 0xFF
            key = key_word >> 8
            key_levels[level] += 1
            level_by_name.setdefault(name, Counter())[level] += 1
            if key_min is None or key < key_min:
                key_min = key
            if key_max is None or key > key_max:
                key_max = key
            if previous_key is not None and name == "CONTAINER":
                if key < previous_key:
                    key_monotonic = False
                if key <= previous_key:
                    key_strictly_increasing = False
            if name == "CONTAINER":
                previous_key = key

            kind = header[0x20]
            count = header[0x21]
            chunk_kinds[kind] += 1
            chunk_counts[count] += 1
            pairs = []
            if count and 0x22 + count * 8 <= 0x40:
                pairs = [
                    struct.unpack_from("<II", header, 0x22 + i * 8)
                    for i in range(count)
                ]
                used_slots[sum(1 for c, u in pairs if c or u)] += 1

            if rows:
                rows.write(json.dumps({
                    "offset": offset,
                    "name": name,
                    "block_size": block_size,
                    "version_word": version,
                    "key_word": key_word,
                    "spatial_key": key,
                    "level": level,
                    "type_word": type_word,
                    "chunk_kind": kind,
                    "chunk_count": count,
                    "chunk_pairs": pairs,
                    "tail_words": header[0x38:0x40].hex(),
                }, separators=(",", ":")) + "\n")

            if total % 5000 == 0:
                print(f"  ...{total} blokova, offset 0x{offset:x}", flush=True)
    finally:
        if rows:
            rows.close()

    file_size = path.stat().st_size
    return {
        "file": str(path),
        "file_size": file_size,
        "block_count": total,
        "covered_bytes": covered,
        "file_coverage": covered / file_size if file_size else 0.0,
        "block_names": dict(names.most_common()),
        "version_words": {f"0x{k:08x}": v for k, v in version_words.most_common()},
        "type_words": dict(type_words.most_common(8)),
        "tail_words": dict(tail_words.most_common(8)),
        "chunk_kinds": dict(chunk_kinds.most_common()),
        "chunk_counts": dict(chunk_counts.most_common()),
        "used_chunk_slots": dict(used_slots.most_common()),
        "levels": dict(sorted(key_levels.items())),
        "levels_by_block_name": {
            name: dict(sorted(counter.items()))
            for name, counter in level_by_name.items()
        },
        "spatial_key_min": key_min,
        "spatial_key_max": key_max,
        "container_key_non_decreasing": key_monotonic,
        "container_key_strictly_increasing": key_strictly_increasing,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0,
                        help="0 = svi blokovi")
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    rows_path = args.output / "blocks.jsonl"
    report = profile(args.atlas, args.limit, rows_path)
    report_path = args.output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))

    lines = []
    for item in sorted(args.output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            digest = hashlib.sha256(item.read_bytes()).hexdigest()
            lines.append(f"{digest}  {item.name}")
    (args.output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")

    print(json.dumps({k: v for k, v in report.items()
                      if k not in ("levels_by_block_name",)},
                     indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
