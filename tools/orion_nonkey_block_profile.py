#!/usr/bin/env python3
"""orion_nonkey_block_profile.py — sta su blokovi bez kljuca (sentinel C).

U PSD3 35.320 CONTAINER blokova ima `C = 0xf0000000`; indeks ih ne moze
naci po kljucu.  Writer mora znati sta su i kako se do njih stize.  Alat
za svaki takav blok raspakuje chunk (dict 1 MiB), procita ime chunka i
imena composite-a iz logicke seme i broji ih; za uzorak belezi i A/B.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_psd_reference_profile import parse_logical_schema  # noqa: E402

SENTINEL = 0xF0000000
FILT = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}]


def run(path: Path, output: Path, limit: int) -> dict[str, object]:
    size = path.stat().st_size
    off = 0; seen = 0
    chunk_names = Counter(); composites = Counter(); a_vals = Counter(); b_vals = Counter()
    sig = Counter(); samples = []
    with path.open("rb") as f:
        while limit == 0 or seen < limit:
            f.seek(off); h = f.read(0x22)
            if len(h) < 0x22: break
            nl = h[0]
            if nl == 0 or nl > 15: break
            bs = struct.unpack_from("<I", h, 0x10)[0]
            if bs < 0x20 or off + bs > size: break
            fc = struct.unpack_from("<I", h, 0x1c)[0]
            if h[1:1 + nl] == b"CONTAINER" and fc == SENTINEL:
                seen += 1
                f.seek(off); b = f.read(bs)
                fa = struct.unpack_from("<H", b, 0x18)[0]; fb = struct.unpack_from("<H", b, 0x1a)[0]
                a_vals[fa] += 1; b_vals[fb >> 8] += 1
                codec = b[0x20]
                if codec == 1:
                    dec = b[0x21:bs - 16]
                else:
                    cnt = b[0x21]; c0, u0 = struct.unpack_from("<II", b, 0x22); d0 = 0x22 + cnt * 8
                    try:
                        dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=FILT).decompress(b[d0:d0 + c0])[:u0]
                    except lzma.LZMAError:
                        chunk_names["<LZMAError>"] += 1; off += bs; continue
                name = dec[1:1 + dec[0]].decode("ascii", "replace") if dec and dec[0] < 32 else "?"
                chunk_names[f"codec{codec}:{name}"] += 1
                schema = parse_logical_schema(dec)
                if schema:
                    names = tuple(sorted({c["name"] for c in schema["composites"]}))
                    sig[names] += 1
                    for nm in names: composites[nm] += 1
                if len(samples) < 6:
                    samples.append({"offset": off, "A": fa, "B": fb >> 8, "codec": codec, "chunk": name,
                                    "composites": list(names) if schema else None})
            off += bs
    report = {"file": str(path), "nonkey_blocks": seen,
              "chunk_names": dict(chunk_names.most_common()),
              "A_values_top": a_vals.most_common(10), "B_values_top": b_vals.most_common(6),
              "composite_names_top": composites.most_common(25),
              "schema_signatures_top": [(list(k), v) for k, v in sig.most_common(12)],
              "samples": samples}
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("atlas", type=Path); ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    print(json.dumps(run(a.atlas, a.output, a.limit), indent=2, ensure_ascii=False)); return 0


if __name__ == "__main__":
    sys.exit(main())
