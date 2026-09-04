#!/usr/bin/env python3
"""orion_atlas_assemble.py — sastavljac kompletne ATLAS baze (svi delovi).

Ulaz je uredjen niz CONTAINER blokova (sirovi bajtovi + A/K iz zaglavlja);
izlaz su fajlovi delova sa HEADER, REVISION, INDEX stablom i blokovima,
po dokazanoj specifikaciji u `docs/ATLAS_CONTAINER.md`:

    deo 0:  HEADER | REVISION | INDEX koren | INDEX listovi | blokovi
    deo k:  HEADER | blokovi

Pravila indeksa (izmerena na originalu):
  * list ima 2048 stavki; poslednji list ima najmanji stepen dvojke >= ostatka;
  * koren ima najmanji stepen dvojke >= broja listova;
  * separator i = (A, K) prvog bloka deteta i+1; popuna ponavlja poslednji
    separator i poslednju stavku;
  * zaglavlje lista na +0x1b nosi (A, K) sopstvenog prvog bloka — isti
    separator kojim roditelj vodi do lista; prvi list i koren nose nule;
  * offseti su globalni (delovi nadovezani), HEADER delova >= 1 se preskace.

Rezim `roundtrip`: uzmi originalnu bazu, sastavi je ponovo iz sopstvenih
blokova sa originalnim granicama delova i uporedi sintetizovane oblasti
(HEADER, REVISION, INDEX) bajt-po-bajt, a raspored blokova offset-po-offset.
To je dokaz da writer ume da napravi fajl koji je identican originalu.
`--write DIR` dodatno upisuje kompletne fajlove.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_index_decode import iter_blocks, read_part_header  # noqa: E402

TERMINATOR = bytes.fromhex("0123456789abcdeffedcba9876543210")
LEAF_ENTRIES = 2048
BLOCK_HEADER_SIZE = 4096
SENTINEL_KEY = 0xF000000000


def align16(v: int) -> int:
    return (v + 15) // 16 * 16


def pow2_at_least(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def index_block_size(entries: int) -> int:
    return align16(0x23 + (entries - 1) * 8 + entries * 8 + entries * 4 + 16)


def named_header(name: bytes, pad: int, size: int, version: bytes) -> bytearray:
    out = bytearray([len(name)]) + name + bytes([pad]) * (0x10 - 1 - len(name))
    out += struct.pack("<I", size) + version
    return out


def build_index_block(level: int, entries: list[tuple[int, int]], separators: list[tuple[int, int]],
                      version: bytes, own_key: tuple[int, int] | None) -> bytes:
    n = pow2_at_least(len(entries))
    size = index_block_size(n)
    out = named_header(b"INDEX", 0xCC, size, version)
    out += bytes([level, n.bit_length() - 1, 1])
    if own_key is None:
        out += b"\x00" * 8
    else:
        a, k = own_key
        out += a.to_bytes(3, "little") + k.to_bytes(5, "little")
    assert len(out) == 0x23
    seps = list(separators)
    if n > 1:
        if not seps:
            raise ValueError("cvor sa vise od jedne stavke mora imati separator")
        seps += [seps[-1]] * (n - 1 - len(seps))
    ents = list(entries) + [entries[-1]] * (n - len(entries))
    for a, k in seps:
        out += a.to_bytes(3, "little") + k.to_bytes(5, "little")
    for off, _ in ents:
        out += struct.pack("<Q", off)
    for _, sz in ents:
        out += struct.pack("<I", sz)
    out += b"\xcc" * (size - 16 - len(out)) + TERMINATOR
    assert len(out) == size
    return bytes(out)


def build_revision(version: bytes, root_size: int, root_offset: int) -> bytes:
    out = named_header(b"REVISION", 0xCC, BLOCK_HEADER_SIZE, version)
    out += struct.pack("<H", 1) + b"\xcc\xcc" + struct.pack("<III", root_size, root_offset, 0)
    out += b"\xcc" * (BLOCK_HEADER_SIZE - 16 - len(out)) + TERMINATOR
    return bytes(out)


def build_header(ref: bytes, part_count: int, part_index: int,
                 total: int, part_size: int, preceding: int) -> bytes:
    """`ref` je originalni HEADER blok cija se nepoznata polja prepisuju."""
    out = bytearray(ref[:BLOCK_HEADER_SIZE])
    out[0x1A] = part_count
    out[0x1B] = part_index
    struct.pack_into("<QQQ", out, 0x48, total, part_size, preceding)
    return bytes(out)


def plan(blocks: list[dict[str, int]], part_sizes: list[int] | None, max_part: int,
         ) -> tuple[list[list[dict[str, int]]], list[tuple[int, int]], int]:
    """Rasporedi blokove u delove; vrati delove, (offset,size) listova, velicinu index zone."""
    leaves = (len(blocks) + LEAF_ENTRIES - 1) // LEAF_ENTRIES
    root_size = index_block_size(pow2_at_least(leaves))
    leaf_sizes = [index_block_size(LEAF_ENTRIES)] * (leaves - 1)
    remaining = len(blocks) - (leaves - 1) * LEAF_ENTRIES
    leaf_sizes.append(index_block_size(pow2_at_least(remaining)))
    zone = 2 * BLOCK_HEADER_SIZE + root_size + sum(leaf_sizes)
    leaf_pos = []
    cursor = 2 * BLOCK_HEADER_SIZE + root_size
    for sz in leaf_sizes:
        leaf_pos.append((cursor, sz)); cursor += sz
    parts: list[list[dict[str, int]]] = [[]]
    local = zone
    part_idx = 0
    for b in blocks:
        limit = part_sizes[part_idx] if part_sizes else max_part
        if local + b["size"] > limit:
            parts.append([]); part_idx += 1; local = BLOCK_HEADER_SIZE
        b["local"] = local
        b["part"] = part_idx
        parts[part_idx].append(b)
        local += b["size"]
    return parts, leaf_pos, zone


def assemble(part_paths: list[Path], write_dir: Path | None, output: Path) -> dict[str, object]:
    parts_meta = sorted((read_part_header(p) for p in part_paths), key=lambda i: i["part_index"])
    views = []
    handles = []
    for m in parts_meta:
        h = m["path"].open("rb"); handles.append(h)
        views.append(mmap.mmap(h.fileno(), 0, access=mmap.ACCESS_READ))
    try:
        ref_header = bytes(views[0][:BLOCK_HEADER_SIZE])
        version = ref_header[0x14:0x18]
        blocks = []
        original_local = []
        for pi, (m, v) in enumerate(zip(parts_meta, views)):
            for off, name, size in iter_blocks(v, m["part_size"]):
                if name != b"CONTAINER":
                    continue
                a = struct.unpack_from("<H", v, off + 0x18)[0]
                b_hi = struct.unpack_from("<H", v, off + 0x1A)[0] >> 8
                c = struct.unpack_from("<I", v, off + 0x1C)[0]
                blocks.append({"size": size, "A": a, "K": (c << 8) | b_hi, "src_part": pi, "src_off": off})
                original_local.append((pi, off))
        part_sizes = [m["part_size"] for m in parts_meta]
        parts, leaf_pos, zone = plan(blocks, part_sizes, 0)

        # globalni offseti
        preceding = []
        acc = 0
        for pi, pb in enumerate(parts):
            preceding.append(acc)
            size = (zone if pi == 0 else BLOCK_HEADER_SIZE) + sum(b["size"] for b in pb)
            acc += size
        total = acc
        for b in blocks:
            b["global"] = preceding[b["part"]] + b["local"]

        # indeks
        leaves_entries = []
        leaves_seps = []
        for i in range(0, len(blocks), LEAF_ENTRIES):
            chunk = blocks[i:i + LEAF_ENTRIES]
            leaves_entries.append([(b["global"], b["size"]) for b in chunk])
            leaves_seps.append([(b["A"], b["K"]) for b in chunk[1:]])
        leaf_blobs = []
        for li, (ents, seps) in enumerate(zip(leaves_entries, leaves_seps)):
            own = None
            if li > 0:
                own = (blocks[li * LEAF_ENTRIES]["A"], blocks[li * LEAF_ENTRIES]["K"])
            leaf_blobs.append(build_index_block(2, ents, seps, version, own))
        root_entries = list(leaf_pos)
        root_seps = [(blocks[(li + 1) * LEAF_ENTRIES]["A"], blocks[(li + 1) * LEAF_ENTRIES]["K"])
                     for li in range(len(leaf_blobs) - 1)]
        root_blob = build_index_block(1, root_entries, root_seps, version, None)
        root_offset = 2 * BLOCK_HEADER_SIZE
        revision_blob = build_revision(version, len(root_blob), root_offset)

        # poredjenje sa originalom
        report: dict[str, object] = {"blocks": len(blocks), "parts": len(parts), "total_size": total,
                                     "index_zone_size": zone, "leaves": len(leaf_blobs)}
        mism = []
        def cmp(pi: int, off: int, blob: bytes, label: str) -> None:
            orig = bytes(views[pi][off:off + len(blob)])
            if orig != blob:
                first = next((i for i in range(len(blob)) if i >= len(orig) or orig[i] != blob[i]), None)
                mism.append({"part": pi, "offset": off, "what": label, "first_diff": first,
                             "orig": orig[first:first + 16].hex() if first is not None and first < len(orig) else None,
                             "ours": blob[first:first + 16].hex() if first is not None else None})
        for pi in range(len(parts)):
            psize = (zone if pi == 0 else BLOCK_HEADER_SIZE) + sum(b["size"] for b in parts[pi])
            cmp(pi, 0, build_header(bytes(views[pi][:BLOCK_HEADER_SIZE]), len(parts), pi, total, psize, preceding[pi]), "HEADER")
        cmp(0, BLOCK_HEADER_SIZE, revision_blob, "REVISION")
        cmp(0, root_offset, root_blob, "INDEX root")
        for (off, _), blob in zip(leaf_pos, leaf_blobs):
            cmp(0, off, blob, "INDEX leaf")
        layout_ok = sum(1 for b, (pi, off) in zip(blocks, original_local) if b["part"] == pi and b["local"] == off)
        report["block_layout_matches"] = layout_ok
        report["synthesized_regions"] = 3 + len(parts) + len(leaf_blobs) - 1
        report["mismatches"] = mism[:20]
        report["mismatch_count"] = len(mism)
        report["part_sizes_match"] = [((zone if pi == 0 else BLOCK_HEADER_SIZE) + sum(b["size"] for b in parts[pi]))
                                      == part_sizes[pi] for pi in range(len(parts))]
        report["exact"] = not mism and layout_ok == len(blocks) and all(report["part_sizes_match"])

        if write_dir is not None:
            write_dir.mkdir(parents=True, exist_ok=True)
            digests = []
            for pi in range(len(parts)):
                psize = (zone if pi == 0 else BLOCK_HEADER_SIZE) + sum(b["size"] for b in parts[pi])
                name = parts_meta[pi]["path"].name if pi < len(parts_meta) else f"part{pi}.ATLAS"
                h = hashlib.md5()
                with (write_dir / name).open("wb") as out:
                    def emit(data: bytes) -> None:
                        out.write(data); h.update(data)
                    emit(build_header(bytes(views[min(pi, len(views) - 1)][:BLOCK_HEADER_SIZE]), len(parts), pi, total, psize, preceding[pi]))
                    if pi == 0:
                        emit(revision_blob); emit(root_blob)
                        for blob in leaf_blobs: emit(blob)
                    for b in parts[pi]:
                        emit(bytes(views[b["src_part"]][b["src_off"]:b["src_off"] + b["size"]]))
                digests.append({"file": name, "size": psize, "md5": h.hexdigest()})
            report["written"] = digests
    finally:
        for v in views: v.close()
        for h in handles: h.close()
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def build_from_blocks(blocks_jsonl: Path, reference_part0: Path, write_dir: Path, base_name: str,
                      max_part: int, output: Path) -> dict[str, object]:
    """Nova baza iz generisanih blokova (`blocks.jsonl`: K, A, size, path), uredjenih po K."""
    specs = [json.loads(l) for l in blocks_jsonl.open()]
    specs.sort(key=lambda b: b["K"])
    blocks = [{"size": int(b["size"]), "A": int(b["A"]), "K": int(b["K"]), "path": b["path"]} for b in specs]
    with reference_part0.open("rb") as f:
        ref_header = f.read(BLOCK_HEADER_SIZE)
    version = ref_header[0x14:0x18]
    parts, leaf_pos, zone = plan(blocks, None, max_part)
    preceding = []; acc = 0
    for pi, pb in enumerate(parts):
        preceding.append(acc)
        acc += (zone if pi == 0 else BLOCK_HEADER_SIZE) + sum(b["size"] for b in pb)
    total = acc
    for b in blocks:
        b["global"] = preceding[b["part"]] + b["local"]
    leaf_blobs = []
    for li in range(0, len(blocks), LEAF_ENTRIES):
        chunk = blocks[li:li + LEAF_ENTRIES]
        own = (chunk[0]["A"], chunk[0]["K"]) if li > 0 else None
        leaf_blobs.append(build_index_block(2, [(b["global"], b["size"]) for b in chunk],
                                            [(b["A"], b["K"]) for b in chunk[1:]], version, own))
    root_seps = [(blocks[(i + 1) * LEAF_ENTRIES]["A"], blocks[(i + 1) * LEAF_ENTRIES]["K"]) for i in range(len(leaf_blobs) - 1)]
    root_blob = build_index_block(1, list(leaf_pos), root_seps, version, None)
    revision_blob = build_revision(version, len(root_blob), 2 * BLOCK_HEADER_SIZE)
    write_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for pi in range(len(parts)):
        psize = (zone if pi == 0 else BLOCK_HEADER_SIZE) + sum(b["size"] for b in parts[pi])
        name = f"{base_name}.{pi}.ATLAS"
        h = hashlib.md5()
        with (write_dir / name).open("wb") as out:
            def emit(data: bytes) -> None:
                out.write(data); h.update(data)
            emit(build_header(ref_header, len(parts), pi, total, psize, preceding[pi]))
            if pi == 0:
                emit(revision_blob); emit(root_blob)
                for blob in leaf_blobs: emit(blob)
            for b in parts[pi]:
                emit(Path(b["path"]).read_bytes())
        written.append({"file": name, "size": psize, "md5": h.hexdigest()})
    report = {"mode": "build", "blocks": len(blocks), "parts": len(parts), "total_size": total,
              "index_zone_size": zone, "leaves": len(leaf_blobs), "written": written, "exact": True,
              "mismatch_count": 0}
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("parts", type=Path, nargs="*", help="originalni delovi baze (roundtrip)")
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--write", type=Path, default=None, help="upisi sastavljene fajlove u ovaj folder")
    ap.add_argument("--blocks", type=Path, default=None, help="build rezim: blocks.jsonl generisanih blokova")
    ap.add_argument("--reference-part0", type=Path, default=None, help="build rezim: originalni deo 0 za HEADER polja")
    ap.add_argument("--base-name", default="APN221EU22093P1664a.5_1")
    ap.add_argument("--max-part-size", type=int, default=2_097_152_000)
    a = ap.parse_args()
    if a.blocks:
        if not (a.reference_part0 and a.write):
            ap.error("build rezim zahteva --reference-part0 i --write")
        r = build_from_blocks(a.blocks, a.reference_part0, a.write, a.base_name, a.max_part_size, a.output)
    else:
        r = assemble(a.parts, a.write, a.output)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r["exact"] else 1


if __name__ == "__main__":
    sys.exit(main())
