#!/usr/bin/env python3
"""orion_block_key_spatial_probe.py — da li je kljuc bloka prostorni?

Kljuc bloka je `K = (u32 na +0x1c) << 8 | visoki bajt u16 na +0x1a`, a
uz njega ide `A = u16 na +0x18`.  Za svaki graph blok (K nije sentinel)
dekoduje se PointLlh i racuna bbox, pa se K i A porede sa geometrijom:

  * Morton kod centra bbox-a na razlicitim dubinama (bitova po osi) i
    razlicitim koordinatnim mapiranjima — koliko gornjih bitova K deli;
  * korelacija K sa lon, lat, i sa redosledom u fajlu;
  * A prema broju tacaka, sirini bbox-a, dubini.

Ispisuju se samo mere; polja se ne imenuju bez jasnog pogotka.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import math
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_graph_spatial_probe import point_columns, schema_names  # noqa: E402
from orion_psd_reference_profile import (  # noqa: E402
    parse_exact_column_table, parse_logical_schema)

SENTINEL = 0xF0000000
FILT = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}]


def morton(x: int, y: int, bits: int) -> int:
    code = 0
    for i in range(bits):
        code |= ((x >> i) & 1) << (2 * i) | ((y >> i) & 1) << (2 * i + 1)
    return code


def morton_yx(x: int, y: int, bits: int) -> int:
    code = 0
    for i in range(bits):
        code |= ((y >> i) & 1) << (2 * i) | ((x >> i) & 1) << (2 * i + 1)
    return code


def common_prefix_bits(a: int, b: int, width: int) -> int:
    for i in range(width - 1, -1, -1):
        if (a >> i) & 1 != (b >> i) & 1:
            return width - 1 - i
    return width


def run(path: Path, output: Path, limit: int) -> dict[str, object]:
    size = path.stat().st_size
    off = 0
    rows = []
    with path.open("rb") as f:
        while limit == 0 or len(rows) < limit:
            f.seek(off); h = f.read(0x22)
            if len(h) < 0x22: break
            nl = h[0]
            if nl == 0 or nl > 15: break
            bs = struct.unpack_from("<I", h, 0x10)[0]
            if bs < 0x20 or off + bs > size: break
            fc = struct.unpack_from("<I", h, 0x1c)[0]
            if h[1:1 + nl] == b"CONTAINER" and fc != SENTINEL and h[0x20] == 3:
                f.seek(off); b = f.read(bs)
                fa = struct.unpack_from("<H", b, 0x18)[0]
                fb = struct.unpack_from("<H", b, 0x1a)[0]
                cnt = b[0x21]
                c0, u0 = struct.unpack_from("<II", b, 0x22)
                d0 = 0x22 + cnt * 8
                try:
                    dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=FILT).decompress(b[d0:d0 + c0])[:u0]
                except lzma.LZMAError:
                    off += bs; continue
                schema = parse_logical_schema(dec)
                if schema and {"PointLlh", "EdgeRoadElement"} <= schema_names(schema):
                    table = parse_exact_column_table(dec, schema)
                    cols = point_columns(dec, schema, table) if table else None
                    if cols and cols[0]:
                        lons, lats = cols
                        rows.append({"offset": off, "A": fa, "B": fb >> 8, "C": fc,
                                     "K": (fc << 8) | (fb >> 8), "n": len(lons),
                                     "block_size": bs, "csize": c0, "usize": u0,
                                     "lon0": min(lons), "lon1": max(lons),
                                     "lat0": min(lats), "lat1": max(lats)})
            off += bs
            if len(rows) % 500 == 0 and rows: print(f"  ...{len(rows)} graph blokova", flush=True)

    # --- mere ---
    n = len(rows)
    report = {"file": str(path), "graph_blocks": n}
    if n < 10:
        report["error"] = "premalo blokova"
        return report
    ks = [r["K"] for r in rows]
    report["K_strictly_increasing_in_file_order"] = all(ks[i] < ks[i + 1] for i in range(n - 1))
    report["K_distinct"] = len(set(ks))
    report["A_range"] = [min(r["A"] for r in rows), max(r["A"] for r in rows)]
    report["B_values"] = dict(Counter(r["B"] for r in rows).most_common(12))
    # sirina bbox po bloku
    wl = [(r["lon1"] - r["lon0"]) / 1e7 for r in rows]
    wt = [(r["lat1"] - r["lat0"]) / 1e7 for r in rows]
    report["bbox_width_deg_lon_median"] = sorted(wl)[n // 2]
    report["bbox_width_deg_lat_median"] = sorted(wt)[n // 2]
    # korelacija (Spearman-lite preko rangova)
    def rank_corr(xs, ys):
        rx = {v: i for i, v in enumerate(sorted(set(xs)))}
        ry = {v: i for i, v in enumerate(sorted(set(ys)))}
        a = [rx[v] for v in xs]; b = [ry[v] for v in ys]
        ma = sum(a) / n; mb = sum(b) / n
        cov = sum((p - ma) * (q - mb) for p, q in zip(a, b))
        va = math.sqrt(sum((p - ma) ** 2 for p in a)); vb = math.sqrt(sum((q - mb) ** 2 for q in b))
        return cov / (va * vb) if va and vb else 0.0
    cl = [(r["lon0"] + r["lon1"]) // 2 for r in rows]
    ct = [(r["lat0"] + r["lat1"]) // 2 for r in rows]
    report["rank_corr_K_lon"] = round(rank_corr(ks, cl), 4)
    report["rank_corr_K_lat"] = round(rank_corr(ks, ct), 4)
    report["rank_corr_A_points"] = round(rank_corr([r["A"] for r in rows], [r["n"] for r in rows]), 4)
    report["rank_corr_A_bboxwidth"] = round(rank_corr([r["A"] for r in rows], [max(a, b) for a, b in zip(wl, wt)]), 4)
    # politika deljenja: velicina dekodiranog chunka po nivou
    by_a = {}
    for r in rows:
        by_a.setdefault(r["A"], []).append(r["usize"])
    report["usize_max"] = max(r["usize"] for r in rows)
    report["usize_by_A"] = {str(a): {"blocks": len(v), "usize_min": min(v), "usize_median": sorted(v)[len(v) // 2],
                                     "usize_max": max(v)} for a, v in sorted(by_a.items())}
    # Morton hipoteze: mapiraj lon/lat u [0, 2^bits) razlicitim sirinama i uporedi prefiks sa K (40 bita)
    best = []
    for bits in (16, 18, 20):
        for lon_span, lat_span, lon_off, lat_off in (
                (360.0, 180.0, 180.0, 90.0), (360.0, 360.0, 180.0, 180.0),
                (180.0, 90.0, 0.0, 0.0), (256.0, 256.0, 128.0, 128.0)):
            for order, fn in (("xy", morton), ("yx", morton_yx)):
                total = 0
                for r in rows[:2000]:
                    x = int(((cl[rows.index(r)] / 1e7) + lon_off) / lon_span * (1 << bits)) & ((1 << bits) - 1)
                    y = int(((ct[rows.index(r)] / 1e7) + lat_off) / lat_span * (1 << bits)) & ((1 << bits) - 1)
                    m = fn(x, y, bits)
                    total += common_prefix_bits(m << (40 - 2 * bits) if 2 * bits <= 40 else m >> (2 * bits - 40), r["K"], 40)
                best.append((total / min(n, 2000), bits, f"{lon_span}x{lat_span} off {lon_off},{lat_off}", order))
    best.sort(reverse=True)
    report["morton_best_avg_common_prefix_bits_of_40"] = [
        {"avg_bits": round(b[0], 2), "bits_per_axis": b[1], "mapping": b[2], "order": b[3]} for b in best[:6]]
    report["morton_random_baseline_bits"] = 1.0
    report["sample_rows"] = rows[:6]
    output.mkdir(parents=True, exist_ok=True)
    with (output / "graph_blocks.jsonl").open("w") as s:
        for r in rows: s.write(json.dumps(r, separators=(",", ":")) + "\n")
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("atlas", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    r = run(a.atlas, a.output, a.limit)
    print(json.dumps({k: v for k, v in r.items() if k != "sample_rows"}, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
