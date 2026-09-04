#!/usr/bin/env python3
"""orion_container_header_decode.py — bajt-po-bajt spec CONTAINER bloka.

Nastavak `orion_atlas_header_decode.py`.  HEADER blok je dokazan preko
vise baza; ovde se ista gramatika proverava na svakom CONTAINER bloku
jednog ATLAS fajla:

    +0x00  u8 len + ime bloka, popuna do 0x10
    +0x10  u32   velicina bloka
    +0x14  u8[4] format verzija {major, minor, rev, 0}
    +0x18  u16   polje A
    +0x1a  u16   polje B
    +0x1c  u32   polje C (`0xf0000000` je sentinel)
    +0x20  u8    chunk codec
    +0x21  u8    broj chunk stavki
    +0x22  (u32 csize, u32 usize) * count
           payload

Proveravaju se stvarni invarianti, ne pretpostavke: poravnanje velicine,
da li `data_offset + zbir(csize)` staje u blok, koliko je popune iza
payload-a, koje su vrednosti popune i da li su polja A/B/C u dokazanom
opsegu.  Skripta ne upisuje u ATLAS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path


def decode_blocks(path: Path, limit: int):
    file_size = path.stat().st_size
    offset = 0
    index = 0
    with path.open("rb") as source:
        while limit == 0 or index < limit:
            source.seek(offset)
            head = source.read(0x400)
            if len(head) < 0x40:
                break
            name_length = head[0]
            if name_length == 0 or name_length > 0x0F:
                break
            name = head[1:1 + name_length].decode("ascii", "replace")
            block_size = struct.unpack_from("<I", head, 0x10)[0]
            if block_size < 0x20 or offset + block_size > file_size:
                break
            count = head[0x21]
            data_offset = 0x22 + count * 8
            pairs = []
            if data_offset <= len(head):
                pairs = [struct.unpack_from("<II", head, 0x22 + i * 8)
                         for i in range(count)]
            yield {
                "offset": offset,
                "name": name,
                "pad_bytes": sorted(set(head[1 + name_length:0x10])),
                "block_size": block_size,
                "version": list(head[0x14:0x18]),
                "field_a": struct.unpack_from("<H", head, 0x18)[0],
                "field_b": struct.unpack_from("<H", head, 0x1A)[0],
                "field_c": struct.unpack_from("<I", head, 0x1C)[0],
                "codec": head[0x20],
                "chunk_count": count,
                "data_offset": data_offset,
                "pairs": pairs,
            }, source
            offset += block_size
            index += 1


def profile(path: Path, limit: int, rows_path: Path) -> dict[str, object]:
    names: Counter[str] = Counter()
    pad_values: Counter[str] = Counter()
    versions: Counter[str] = Counter()
    codecs: Counter[int] = Counter()
    counts: Counter[int] = Counter()
    used_slots: Counter[int] = Counter()
    field_a: Counter[int] = Counter()
    field_b_low: Counter[int] = Counter()
    field_c_sentinel = 0
    field_c_values: list[int] = []
    alignment: Counter[int] = Counter()
    trailer_sizes: Counter[int] = Counter()
    trailer_bytes: Counter[str] = Counter()

    overflow = 0
    total = 0
    covered = 0

    with rows_path.open("w", encoding="utf-8") as rows:
        for block, source in decode_blocks(path, limit):
            total += 1
            covered += block["block_size"]
            names[block["name"]] += 1
            pad_values["+".join(f"{b:02x}" for b in block["pad_bytes"])] += 1
            versions[".".join(str(v) for v in block["version"])] += 1
            codecs[block["codec"]] += 1
            counts[block["chunk_count"]] += 1
            field_a[block["field_a"]] += 1
            field_b_low[block["field_b"] & 0xFF] += 1
            if block["field_c"] == 0xF0000000:
                field_c_sentinel += 1
            else:
                field_c_values.append(block["field_c"])

            used = sum(1 for c, u in block["pairs"] if c or u)
            used_slots[used] += 1
            payload = sum(c for c, _ in block["pairs"])
            end = block["data_offset"] + payload
            if end > block["block_size"]:
                overflow += 1
            trailer = block["block_size"] - end
            trailer_sizes[trailer] += 1
            alignment[block["block_size"] % 16] += 1

            if 0 < trailer <= 64:
                source.seek(block["offset"] + end)
                trailer_bytes["+".join(
                    f"{b:02x}" for b in sorted(set(source.read(trailer))))] += 1

            rows.write(json.dumps({
                k: v for k, v in block.items() if k != "pad_bytes"
            }, separators=(",", ":")) + "\n")

            if total % 5000 == 0:
                print(f"  ...{total} blokova", flush=True)

    file_size = path.stat().st_size
    values = sorted(field_c_values)
    return {
        "file": str(path),
        "file_size": file_size,
        "block_count": total,
        "file_coverage": covered / file_size if file_size else 0.0,
        "block_names": dict(names.most_common()),
        "name_padding_values": dict(pad_values.most_common()),
        "versions": dict(versions.most_common()),
        "chunk_codecs": dict(codecs.most_common()),
        "chunk_counts": dict(counts.most_common()),
        "used_chunk_slots": dict(used_slots.most_common()),
        "field_a_values": dict(sorted(field_a.items())),
        "field_b_low_byte_values": dict(sorted(field_b_low.items())),
        "field_c_sentinel_count": field_c_sentinel,
        "field_c_value_count": len(values),
        "field_c_min": values[0] if values else None,
        "field_c_max": values[-1] if values else None,
        "field_c_distinct": len(set(values)),
        "block_size_alignment_mod16": dict(sorted(alignment.items())),
        "payload_overflow_count": overflow,
        "trailer_sizes": dict(trailer_sizes.most_common(12)),
        "trailer_byte_values": dict(trailer_bytes.most_common(8)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    report = profile(args.atlas, args.limit, args.output / "blocks.jsonl")
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False))
    lines = []
    for item in sorted(args.output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
    (args.output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")

    show = {k: v for k, v in report.items()
            if k not in ("field_a_values", "field_b_low_byte_values")}
    show["field_a_range"] = [min(report["field_a_values"]), max(report["field_a_values"])]
    show["field_b_low_byte_distinct"] = len(report["field_b_low_byte_values"])
    print(json.dumps(show, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
