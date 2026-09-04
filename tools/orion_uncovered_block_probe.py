#!/usr/bin/env python3
"""orion_uncovered_block_probe.py — blokovi koje INDEX listovi ne pokrivaju.

Listovi pokrivaju neprekidan opseg baze od prvog offseta prvog lista do
kraja poslednjeg dela.  U delu 0 pre tog opsega stoje HEADER, REVISION,
INDEX blokovi i — po merenju — jos CONTAINER blokova.  Alat ih nabraja
(ime, codec, A/B/C, ime chunka, composite imena) da bi writer znao sta
mora da stoji ispred indeksiranog dela i kako se do toga stize.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import mmap
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_index_decode import decode_index_block, iter_blocks, read_part_header  # noqa: E402
from orion_psd_reference_profile import parse_logical_schema  # noqa: E402

FILT = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}]


def run(part0: Path, output: Path) -> dict[str, object]:
    hdr = read_part_header(part0)
    fh = part0.open("rb"); view = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        first_leaf_offset = None
        blocks = list(iter_blocks(view, hdr["part_size"]))
        for off, name, size in blocks:
            if name == b"INDEX":
                d = decode_index_block(view, off, size)
                if d.get("level") == 2:
                    first_leaf_offset = d["offsets"][0]; break
        rows = []; names = Counter(); chunk = Counter(); comps = Counter()
        for off, name, size in blocks:
            if off >= first_leaf_offset: break
            names[name.decode()] += 1
            if name != b"CONTAINER": continue
            fa = struct.unpack_from("<H", view, off + 0x18)[0]; fb = struct.unpack_from("<H", view, off + 0x1a)[0]
            fc = struct.unpack_from("<I", view, off + 0x1c)[0]; codec = view[off + 0x20]
            if codec == 1:
                dec = bytes(view[off + 0x21:off + size - 16])
            else:
                cnt = view[off + 0x21]; c0, u0 = struct.unpack_from("<II", view, off + 0x22); d0 = off + 0x22 + cnt * 8
                try:
                    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=FILT).decompress(bytes(view[d0:d0 + c0]))[:u0]
                except lzma.LZMAError:
                    dec = b""
            cname = dec[1:1 + dec[0]].decode("ascii", "replace") if dec and dec[0] < 32 else "?"
            chunk[f"codec{codec}:{cname}"] += 1
            schema = parse_logical_schema(dec) if dec else None
            cn = sorted({c["name"] for c in schema["composites"]}) if schema else []
            for c in cn: comps[c] += 1
            rows.append({"offset": off, "size": size, "A": fa, "B": fb >> 8, "C": hex(fc), "codec": codec,
                         "chunk": cname, "usize": len(dec), "composites": cn[:12]})
        report = {"part0": str(part0), "first_leaf_offset": first_leaf_offset,
                  "blocks_before_first_leaf": dict(names), "uncovered_container_blocks": len(rows),
                  "chunk_names": dict(chunk.most_common()), "composite_names_top": comps.most_common(20),
                  "rows": rows}
    finally:
        view.close(); fh.close()
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("part0", type=Path); ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    r = run(a.part0, a.output)
    print(json.dumps({k: v for k, v in r.items() if k != "rows"}, indent=2, ensure_ascii=False))
    for row in r["rows"][:12]: print(" ", row)
    return 0


if __name__ == "__main__":
    sys.exit(main())
