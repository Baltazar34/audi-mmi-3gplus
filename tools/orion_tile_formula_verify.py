#!/usr/bin/env python3
"""orion_tile_formula_verify.py — egzaktna formula kljuca bloka iz geometrije.

Dokazano na PSD delovima 0 i 2 (103.188 + 7.015 graph blokova, 100%):

Jedno globalno binarno stablo nad pohranjenim koordinatama (`degree x 1e7`,
sidreno na nuli, signed) koje na svakom nivou deli jednu osu, naizmenicno:

    nivo A  ->  lon stranica 2^p, lat stranica 2^q
                p = (A + 17) // 2,  q = (A + 16) // 2
    pocetak celije:  x0 = lon0 >> p << p,   y0 = lat0 >> q << q

40-bitni kljuc bloka (`K = C << 8 | B_hi`):

    X = (x0 >> 17) + XOFF,   XOFF = 0x44000
    Y = (y0 >> 17) + YOFF,   YOFF = 0x2000
    K = interleave20(X, Y)   -- Z-preplet, bit Y u visem bitu svakog para

Pomaci XOFF/YOFF drze X i Y pozitivnim za zapadnu hemisferu; nisu geografski
pomak nego pomak u prostoru kljuca.  Krupnija celija automatski ima nule u
nizim bitovima kljuca.  `A` ide od 18 (najfinije) do 28.

Provere po bloku: bbox staje u celiju i `K` se poklapa.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

XOFF = 0x44000
YOFF = 0x2000
FINEST_SHIFT = 17
KEY_BITS_PER_AXIS = 20


def exponents(A: int) -> tuple[int, int]:
    return (A + 17) // 2, (A + 16) // 2


def interleave(x: int, y: int, bits: int = KEY_BITS_PER_AXIS, y_high: bool = True) -> int:
    x &= (1 << bits) - 1
    y &= (1 << bits) - 1
    c = 0
    for i in range(bits):
        lo, hi = (x, y) if y_high else (y, x)
        c |= ((lo >> i) & 1) << (2 * i) | ((hi >> i) & 1) << (2 * i + 1)
    return c


def deinterleave(k: int, bits: int = KEY_BITS_PER_AXIS, y_high: bool = True) -> tuple[int, int]:
    x = y = 0
    for i in range(bits):
        lo = (k >> (2 * i)) & 1
        hi = (k >> (2 * i + 1)) & 1
        if y_high:
            x |= lo << i; y |= hi << i
        else:
            y |= lo << i; x |= hi << i
    return x, y


def cell_origin(r: dict[str, int]) -> tuple[int, int, int, int]:
    p, q = exponents(r["A"])
    return (r["lon0"] >> p) << p, (r["lat0"] >> q) << q, p, q


def block_key(A: int, lon0: int, lat0: int) -> int:
    x0, y0, _, _ = cell_origin({"A": A, "lon0": lon0, "lat0": lat0})
    return interleave((x0 >> FINEST_SHIFT) + XOFF, (y0 >> FINEST_SHIFT) + YOFF)


def run(rows_path: Path, output: Path) -> dict[str, object]:
    rows = [json.loads(l) for l in rows_path.open()]
    n = len(rows)
    report: dict[str, object] = {"blocks": n, "A_range": [min(r["A"] for r in rows), max(r["A"] for r in rows)]}

    fits = 0
    for r in rows:
        x0, y0, p, q = cell_origin(r)
        if r["lon1"] < x0 + (1 << p) and r["lat1"] < y0 + (1 << q):
            fits += 1
    report["bbox_fits_cell"] = fits

    # nezavisno: izvedi pomake iz podataka i proveri da su konstantni
    offsets = Counter()
    for r in rows:
        x0, y0, _, _ = cell_origin(r)
        X, Y = deinterleave(r["K"])
        offsets[(X - (x0 >> FINEST_SHIFT), Y - (y0 >> FINEST_SHIFT))] += 1
    (dx, dy), top = offsets.most_common(1)[0]
    report["derived_offsets"] = {"XOFF": hex(dx), "YOFF": hex(dy), "blocks_with_these": top}
    report["offsets_match_constants"] = (dx, dy) == (XOFF, YOFF)

    hits = 0
    misses = []
    for r in rows:
        k = block_key(r["A"], r["lon0"], r["lat0"])
        if k == r["K"]:
            hits += 1
        elif len(misses) < 8:
            misses.append({"offset": r["offset"], "A": r["A"], "K": hex(r["K"]), "K_calc": hex(k),
                           "bbox": [r["lon0"], r["lat0"], r["lon1"], r["lat1"]]})
    report["K_formula_hits"] = hits
    report["exact"] = hits == n and fits == n and report["offsets_match_constants"]
    report["miss_samples"] = misses
    report["formula"] = {"XOFF": hex(XOFF), "YOFF": hex(YOFF), "finest_shift": FINEST_SHIFT,
                         "bits_per_axis": KEY_BITS_PER_AXIS, "y_high": True,
                         "p": "(A+17)//2", "q": "(A+16)//2"}
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("graph_blocks", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    r = run(a.graph_blocks, a.output)
    print(json.dumps(r, indent=2, ensure_ascii=False))
    return 0 if r["exact"] else 1


if __name__ == "__main__":
    sys.exit(main())
