#!/usr/bin/env python3
"""orion_block_grammar_verify.py — svaki bajt ATLAS bloka mora biti objasnjen.

Tvrda provera, ne profil.  Dokazana podela CONTAINER bloka je:

    +0x00                 u8 len + ime, popuna do 0x10
    +0x10                 u32 velicina bloka
    +0x14                 u8[4] format verzija
    +0x18                 u16 A, u16 B, u32 C
    +0x20                 u8 codec
    codec 1 (nekompresovano): payload odmah na +0x21
    codec 3 (LZMA1 raw):      u8 count na +0x21, pa
                              (u32 csize, u32 usize) * count, pa payload
    ...                   popuna
    block_size-16         terminator 0123456789abcdeffedcba9876543210

Terminator je uvek poslednjih 16 B bloka, ne odmah iza payload-a; ranija
pretpostavka je bila pogresna i ispravljena je merenjem.  Iz toga sledi
jedini potreban velicinski invariant:

    block_size == align16(data_offset + payload + 16)

Popuna izmedju payload-a i terminatora je debug fill (0xca..0xcc) i ne
nosi podatak, pa se proverava samo njen opseg, ne tacna vrednost.

Dekodirani chunk uvek pocinje kao `u8 duzina + ime` ("Map", "VidTable").
Kod codec 1 to ime stoji direktno u bloku na +0x21, pa se tako i
proverava; kod codec 3 stoji na pocetku raspakovanog payload-a.

`HEADER` blok ima drugaciji sadrzaj od `+0x20` i proverava se posebno:
fiksna velicina 4096 i isti terminator na kraju.
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
ALIGNMENT = 16
FILL_BYTES = {0xCA, 0xCB, 0xCC}


def align16(value: int) -> int:
    return (value + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT


def verify(path: Path, limit: int) -> dict[str, object]:
    file_size = path.stat().st_size
    offset = 0
    index = 0
    covered = 0
    ok = 0
    failures: list[dict[str, object]] = []
    reasons: Counter[str] = Counter()
    by_codec: Counter[int] = Counter()
    ok_by_codec: Counter[int] = Counter()
    fill_sizes: Counter[int] = Counter()
    index_zone = 0
    fill_values: Counter[str] = Counter()
    slots_used: Counter[int] = Counter()
    stored_names: Counter[str] = Counter()

    with path.open("rb") as source:
        while limit == 0 or index < limit:
            source.seek(offset)
            head = source.read(0x40)
            if len(head) < 0x40:
                break
            name_length = head[0]
            if name_length == 0 or name_length > 0x0F:
                break
            block_size = struct.unpack_from("<I", head, 0x10)[0]
            if block_size < 0x20 or offset + block_size > file_size:
                break

            source.seek(offset)
            block = source.read(block_size)
            index += 1
            covered += block_size
            name = block[1:1 + name_length].decode("ascii", "replace")

            reason = None
            codec = None
            if block[-ALIGNMENT:] != TERMINATOR:
                reason = "terminator nije poslednjih 16 B"
            elif block_size % ALIGNMENT:
                reason = "velicina nije visekratnik 16"
            elif len(set(block[1 + name_length:0x10])) > 1:
                reason = "popuna imena nije jednobajtna"
            elif name == "HEADER":
                if block_size != 4096:
                    reason = "HEADER nije 4096 B"
            elif name in ("REVISION", "INDEX"):
                # indeksna zona: unutrasnji raspored proverava orion_index_decode.py
                index_zone += 1
            else:
                codec = block[0x20]
                by_codec[codec] += 1
                if codec == 1:
                    name_len = block[0x21]
                    chunk_name = block[0x22:0x22 + name_len]
                    if not (0 < name_len <= 32) or not chunk_name.isascii() \
                            or not chunk_name.isalnum():
                        reason = "codec 1: payload ne pocinje imenom chunka"
                    else:
                        stored_names[chunk_name.decode()] += 1
                        fill_sizes[0] += 1
                    offset += block_size
                    if reason is None:
                        ok += 1
                        ok_by_codec[codec] += 1
                    else:
                        reasons[reason] += 1
                        if len(failures) < 40:
                            failures.append({"offset": offset - block_size,
                                             "name": name,
                                             "block_size": block_size,
                                             "reason": reason})
                    if index % 10000 == 0:
                        print(f"  ...{index} blokova, {ok} objasnjeno", flush=True)
                    continue
                count = block[0x21]
                data_offset = 0x22 + count * 8
                if data_offset + ALIGNMENT > block_size:
                    reason = "chunk tabela ne staje u blok"
                else:
                    pairs = [struct.unpack_from("<II", block, 0x22 + i * 8)
                             for i in range(count)]
                    slots_used[sum(1 for c, u in pairs if c or u)] += 1
                    payload = sum(compressed for compressed, _ in pairs)
                    expected = align16(data_offset + payload + ALIGNMENT)
                    if expected != block_size:
                        reason = (f"velicina ne prati align16(data+payload+16): "
                                  f"ocekivano {expected}")
                    else:
                        fill = block[data_offset + payload:block_size - ALIGNMENT]
                        fill_sizes[len(fill)] += 1
                        extra = set(fill) - FILL_BYTES
                        if extra:
                            reason = "popuna sadrzi bajtove van debug opsega"
                        else:
                            fill_values["+".join(f"{b:02x}" for b in sorted(set(fill)))] += 1

            if reason is None:
                ok += 1
                if codec is not None:
                    ok_by_codec[codec] += 1
            else:
                reasons[reason] += 1
                if len(failures) < 40:
                    failures.append({"offset": offset, "name": name,
                                     "block_size": block_size, "reason": reason})

            offset += block_size
            if index % 10000 == 0:
                print(f"  ...{index} blokova, {ok} objasnjeno", flush=True)

    return {
        "file": str(path),
        "file_size": file_size,
        "block_count": index,
        "file_coverage": covered / file_size if file_size else 0.0,
        "fully_explained": ok,
        "index_zone_blocks": index_zone,
        "not_explained": index - ok,
        "blocks_by_codec": dict(by_codec.most_common()),
        "explained_by_codec": dict(ok_by_codec.most_common()),
        "used_chunk_slots": dict(slots_used.most_common()),
        "fill_size_range": [min(fill_sizes), max(fill_sizes)] if fill_sizes else None,
        "fill_byte_sets": dict(fill_values.most_common(6)),
        "stored_codec1_chunk_names": dict(stored_names.most_common(8)),
        "failure_reasons": dict(reasons.most_common()),
        "failure_samples": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    report = verify(args.atlas, args.limit)
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False))
    lines = []
    for item in sorted(args.output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
    (args.output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")

    show = dict(report)
    show["failure_samples"] = report["failure_samples"][:6]
    print(json.dumps(show, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
