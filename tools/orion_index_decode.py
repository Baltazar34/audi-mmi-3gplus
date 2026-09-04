#!/usr/bin/env python3
"""orion_index_decode.py — dekoder i validator ATLAS `INDEX` direktorijuma.

`INDEX` blokovi postoje samo u nultom delu baze, izmedju `REVISION` bloka i
prvog `CONTAINER` bloka.  Zato ih raniji rad nad PSD3 (deo 2) nije video.

Raspored jednog INDEX bloka:

    +0x00  u8 len + "INDEX", popuna 0xcc do 0x10
    +0x10  u32 velicina bloka
    +0x14  u8[4] format verzija
    +0x18  u8 nivo (1 = koren, 2 = list)
    +0x19  u8 log2(broj stavki)
    +0x1a  u8 1, pa nule do +0x23
    +0x23  (broj stavki - 1) separatora po 8 B
    ...    broj stavki offseta, u64 little-endian
    ...    broj stavki velicina, u32 little-endian
    ...    popuna 5 B, pa terminator 16 B

Separator je `u24 A (little-endian) | u40 K (little-endian)` i predstavlja
kopiju zaglavlja **sledeceg** bloka:

    A = u16 na +0x18 tog CONTAINER bloka
    K = (u32 na +0x1c) << 8 | (visoki bajt u16 na +0x1a)

Dakle `key[i]` opisuje blok `i+1`, kao klasican separator u sortiranom
direktorijumu.  `K` je strogo rastuci dok traju stvarni kljucevi; blokovi
bez kljuca nose sentinel `0xf0000000` u polju na +0x1c, pa im je
`K = 0xf000000000`.

Offset je u adresnom prostoru cele baze: delovi se nadovezuju redom, sa
pomerajem `preceding_size` iz `HEADER` bloka svakog dela.  Unutar
direktorijuma vazi `offset[i] + size[i] == offset[i+1]`, uz dva izuzetka:

  * na granici dva dela preskace se `HEADER` blok narednog dela (4096 B);
  * posle poslednje stvarne stavke, ciji je `offset + size` tacno kraj
    baze, ostatak poslednjeg lista je popunjen ponavljanjem te iste
    stavke.

Semantika `K` i `A` nije imenovana.  Dokazano je samo da su to kopije
zaglavlja bloka i da je `K` sortirni kljuc.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
import sys
from collections import Counter
from pathlib import Path

TERMINATOR_SIZE = 16
DIRECTORY_START = 0x23
HEADER_BLOCK_SIZE = 4096
SENTINEL_KEY = 0xF000000000


def read_part_header(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        block = source.read(0x60)
    return {
        "path": path,
        "part_index": block[0x1B],
        "part_size": struct.unpack_from("<Q", block, 0x50)[0],
        "preceding_size": struct.unpack_from("<Q", block, 0x58)[0],
    }


def iter_blocks(view, file_size: int):
    offset = 0
    while offset + 0x20 <= file_size:
        name_length = view[offset]
        if name_length == 0 or name_length > 0x0F:
            break
        name = bytes(view[offset + 1:offset + 1 + name_length])
        block_size = struct.unpack_from("<I", view, offset + 0x10)[0]
        if block_size < 0x20 or offset + block_size > file_size:
            break
        yield offset, name, block_size
        offset += block_size


def decode_index_block(view, offset: int, block_size: int) -> dict[str, object]:
    entries = 1 << view[offset + 0x19]
    keys_end = DIRECTORY_START + (entries - 1) * 8
    offsets_end = keys_end + entries * 8
    sizes_end = offsets_end + entries * 4
    if sizes_end > block_size - TERMINATOR_SIZE:
        return {"error": "raspored ne staje u blok"}
    separators = []
    for i in range(entries - 1):
        base = offset + DIRECTORY_START + i * 8
        separators.append((
            int.from_bytes(view[base:base + 3], "little"),
            int.from_bytes(view[base + 3:base + 8], "little"),
        ))
    offsets = [int.from_bytes(view[offset + keys_end + i * 8:
                                   offset + keys_end + i * 8 + 8], "little")
               for i in range(entries)]
    sizes = [int.from_bytes(view[offset + offsets_end + i * 4:
                                 offset + offsets_end + i * 4 + 4], "little")
             for i in range(entries)]
    return {
        "level": view[offset + 0x18],
        "entries": entries,
        "separators": separators,
        "offsets": offsets,
        "sizes": sizes,
        "trailing": block_size - TERMINATOR_SIZE - sizes_end,
    }


def run(paths: list[Path], output: Path) -> dict[str, object]:
    parts = sorted((read_part_header(path) for path in paths),
                   key=lambda item: item["part_index"])
    total_size = sum(item["part_size"] for item in parts)
    handles, views = [], []
    for item in parts:
        handle = item["path"].open("rb")
        handles.append(handle)
        views.append(mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ))

    def resolve(global_offset: int):
        for item, view in zip(parts, views):
            local = global_offset - item["preceding_size"]
            if 0 <= local < item["part_size"]:
                return view, local
        return None, None

    stats = Counter()
    failures: list[str] = []
    directories = []
    try:
        root_view, root_size = views[0], parts[0]["part_size"]
        index_blocks = []
        for offset, name, block_size in iter_blocks(root_view, root_size):
            if name == b"CONTAINER":
                break
            if name == b"INDEX":
                index_blocks.append((offset, block_size))

        previous_end = None
        for offset, block_size in index_blocks:
            decoded = decode_index_block(root_view, offset, block_size)
            if "error" in decoded:
                failures.append(f"INDEX @0x{offset:x}: {decoded['error']}")
                continue
            separators = decoded["separators"]
            offsets, sizes = decoded["offsets"], decoded["sizes"]
            # popuna na kraju ponavlja poslednju stavku; strogost se meri samo do nje
            real_entries = len(offsets)
            for i in range(1, len(offsets)):
                if (offsets[i], sizes[i]) == (offsets[i - 1], sizes[i - 1]):
                    real_entries = i
                    break
            real = [k for _, k in separators[:max(0, real_entries - 1)] if k != SENTINEL_KEY]
            if all(real[i] < real[i + 1] for i in range(len(real) - 1)):
                stats["kljucevi strogo rastuci"] += 1
            else:
                failures.append(f"INDEX @0x{offset:x}: kljucevi nisu rastuci")

            if decoded["level"] == 2:
                for i in range(len(offsets) - 1):
                    if offsets[i] + sizes[i] == total_size:
                        if (offsets[i + 1], sizes[i + 1]) == (offsets[i], sizes[i]):
                            stats["popuna na kraju baze"] += 1
                            continue
                        failures.append(
                            f"INDEX @0x{offset:x} stavka {i}: neispravna popuna")
                        continue
                    stats["stavki"] += 1
                    gap = offsets[i + 1] - (offsets[i] + sizes[i])
                    if gap == 0:
                        stats["stavke neprekidne"] += 1
                    elif gap == HEADER_BLOCK_SIZE:
                        stats["granica dela (preskocen HEADER)"] += 1
                    else:
                        failures.append(
                            f"INDEX @0x{offset:x} stavka {i}: rupa {gap} B")
                    view, local = resolve(offsets[i + 1])
                    if view is None:
                        failures.append(f"offset 0x{offsets[i + 1]:x} nerazresiv")
                        continue
                    if struct.unpack_from("<I", view, local + 0x10)[0] != sizes[i + 1]:
                        failures.append(f"velicina se ne poklapa @0x{offsets[i+1]:x}")
                        continue
                    stats["velicina potvrdjena u bloku"] += 1
                    name_length = view[local]
                    if bytes(view[local + 1:local + 1 + name_length]) != b"CONTAINER":
                        continue
                    field_a = struct.unpack_from("<H", view, local + 0x18)[0]
                    field_b = struct.unpack_from("<H", view, local + 0x1A)[0]
                    field_c = struct.unpack_from("<I", view, local + 0x1C)[0]
                    sep_a, sep_k = separators[i]
                    if sep_k == ((field_c << 8) | (field_b >> 8)):
                        stats["kljuc == zaglavlje sledeceg bloka"] += 1
                    else:
                        failures.append(f"kljuc != zaglavlje @0x{offsets[i+1]:x}")
                    if sep_a == field_a:
                        stats["polje A == zaglavlje sledeceg bloka"] += 1
                    else:
                        failures.append(f"A != zaglavlje @0x{offsets[i+1]:x}")

                if previous_end is not None:
                    if previous_end == offsets[0]:
                        stats["lanac listova neprekidan"] += 1
                    else:
                        failures.append(f"INDEX @0x{offset:x}: prekid lanca listova")
                previous_end = offsets[-1] + sizes[-1]

            directories.append({
                "block_offset": offset,
                "block_size": block_size,
                "level": decoded["level"],
                "entries": decoded["entries"],
                "trailing": decoded["trailing"],
                "real_key_count": len(real),
                "sentinel_key_count": len(separators) - len(real),
                "first_offset": offsets[0],
                "last_offset": offsets[-1],
                "last_size": sizes[-1],
            })

        block_totals = Counter()
        for item, view in zip(parts, views):
            for _, name, _ in iter_blocks(view, item["part_size"]):
                block_totals[name.decode()] += 1
    finally:
        for view in views:
            view.close()
        for handle in handles:
            handle.close()

    leaves = [d for d in directories if d["level"] == 2]
    report = {
        "database_total_size": total_size,
        "part_count": len(parts),
        "index_block_count": len(directories),
        "root_blocks": len(directories) - len(leaves),
        "leaf_blocks": len(leaves),
        "leaf_entry_total": sum(d["entries"] for d in leaves),
        "blocks_in_database": dict(block_totals.most_common()),
        "blocks_total": sum(block_totals.values()),
        "real_keys": sum(d["real_key_count"] for d in leaves),
        "sentinel_keys": sum(d["sentinel_key_count"] for d in leaves),
        "checks": dict(stats),
        "failure_count": len(failures),
        "failure_samples": failures[:20],
        "boundary": (
            "Semantika kljuca K i polja A nije imenovana; dokazano je samo da "
            "su kopije zaglavlja sledeceg bloka i da je K sortirni kljuc."
        ),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    with (output / "directories.jsonl").open("w", encoding="utf-8") as stream:
        for entry in directories:
            stream.write(json.dumps(entry, separators=(",", ":")) + "\n")
    lines = []
    for item in sorted(output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("parts", type=Path, nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.parts, args.output)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report["failure_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
