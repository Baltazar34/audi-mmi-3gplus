#!/usr/bin/env python3
"""orion_tile_grid_probe.py — formula tile ID-a (C), putanje (B) i nivoa (A).

Ulaz je `graph_blocks.jsonl` iz `orion_block_key_spatial_probe.py`: po
bloku A, B, C, K i bbox u `degree x 1e7`.  Hipoteze koje se mere:

  * C je ID tile-a: blokovi sa istim C imaju bbox unutar jednog tile-a;
    tile bbox = unija.  Meri se raspodela sirina tile-ova.
  * A je nivo: sirina bloka ~ 2^(A-k) jedinica.  Meri se A - log2(sirina).
  * B je putanja kroz kvadratnu podelu tile-a: po nivou se racuna kvadrant
    centra bloka u odnosu na tile bbox i poredi sa bitovima B, za sve
    kombinacije redosleda (xy/yx) i orijentacije y-ose.
  * C prema mrezi: tile_x/tile_y iz bbox-a i pokusaj da se C izrazi kao
    row-major, column-major ili Morton indeks te mreze.

Izlaz su samo mere; imena se dodeljuju tek kad pogodak bude egzaktan.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path


def log2i(v: float) -> float:
    return math.log2(v) if v > 0 else float("nan")


def morton(x: int, y: int, bits: int) -> int:
    c = 0
    for i in range(bits):
        c |= ((x >> i) & 1) << (2 * i) | ((y >> i) & 1) << (2 * i + 1)
    return c


def run(rows_path: Path, output: Path) -> dict[str, object]:
    rows = [json.loads(l) for l in rows_path.open()]
    report: dict[str, object] = {"blocks": len(rows)}

    # --- A prema sirini bloka ---
    diff_lon = Counter(); diff_lat = Counter()
    for r in rows:
        wl = r["lon1"] - r["lon0"]; wt = r["lat1"] - r["lat0"]
        if wl > 0: diff_lon[round(r["A"] - log2i(wl), 1)] += 1
        if wt > 0: diff_lat[round(r["A"] - log2i(wt), 1)] += 1
    report["A_minus_log2_lon_width_top"] = diff_lon.most_common(6)
    report["A_minus_log2_lat_width_top"] = diff_lat.most_common(6)

    # --- tile bbox po C ---
    tiles: dict[int, dict[str, int]] = {}
    per_tile = defaultdict(list)
    for r in rows:
        per_tile[r["C"]].append(r)
        t = tiles.setdefault(r["C"], {"lon0": r["lon0"], "lon1": r["lon1"], "lat0": r["lat0"], "lat1": r["lat1"]})
        t["lon0"] = min(t["lon0"], r["lon0"]); t["lon1"] = max(t["lon1"], r["lon1"])
        t["lat0"] = min(t["lat0"], r["lat0"]); t["lat1"] = max(t["lat1"], r["lat1"])
    report["tiles"] = len(tiles)
    report["blocks_per_tile_top"] = Counter(len(v) for v in per_tile.values()).most_common(8)
    tw = Counter(); th = Counter()
    for t in tiles.values():
        tw[round(log2i(t["lon1"] - t["lon0"]), 1)] += 1
        th[round(log2i(t["lat1"] - t["lat0"]), 1)] += 1
    report["tile_log2_lon_width_top"] = tw.most_common(6)
    report["tile_log2_lat_height_top"] = th.most_common(6)

    # --- B kao kvadratna putanja unutar tile-a (samo tile-ovi sa >=4 bloka) ---
    # Nivo tile-a: uzmi max A u tile-u kao koren, blok na nivou A ima dubinu (rootA - A).
    def quad_path(r, t, depth, order, yflip):
        cx = (r["lon0"] + r["lon1"]) / 2; cy = (r["lat0"] + r["lat1"]) / 2
        x0, x1, y0, y1 = t["lon0"], t["lon1"], t["lat0"], t["lat1"]
        bits = 0
        for _ in range(depth):
            xm = (x0 + x1) / 2; ym = (y0 + y1) / 2
            bx = 1 if cx >= xm else 0
            by = 1 if cy >= ym else 0
            if yflip: by ^= 1
            pair = (bx << 1 | by) if order == "xy" else (by << 1 | bx)
            bits = (bits << 2) | pair
            x0, x1 = (xm, x1) if cx >= xm else (x0, xm)
            y0, y1 = (ym, y1) if cy >= ym else (y0, ym)
        return bits
    scores = Counter(); tested = 0
    for c, blocks in per_tile.items():
        if len(blocks) < 4: continue
        t = tiles[c]
        root_a = max(b["A"] for b in blocks) + 1   # koren je za jedan nivo iznad najkrupnijeg bloka
        for b in blocks:
            depth = root_a - b["A"]
            if depth <= 0 or depth > 4: continue
            tested += 1
            for order in ("xy", "yx"):
                for yflip in (False, True):
                    path = quad_path(b, t, depth, order, yflip)
                    # B je 8-bitni prefiks: gornjih 2*depth bita
                    if (b["B"] >> (8 - 2 * depth)) == path:
                        scores[f"{order} yflip={yflip}"] += 1
    report["quad_path_tested"] = tested
    report["quad_path_matches"] = dict(scores.most_common())

    # --- C prema mrezi tile-ova ---
    # pretpostavi kvadratnu mrezu sirine W (mod log2 sirine tile-a)
    if tiles:
        W = 1 << int(round(tw.most_common(1)[0][0])); H = 1 << int(round(th.most_common(1)[0][0]))
        report["grid_cell_lon_units"] = W; report["grid_cell_lat_units"] = H
        pts = []
        for c, t in tiles.items():
            tx = t["lon0"] // W; ty = t["lat0"] // H
            pts.append((c, tx, ty))
        pts.sort()
        # susedni C: pomak u tx/ty
        step = Counter()
        for (c0, x0, y0), (c1, x1, y1) in zip(pts, pts[1:]):
            if c1 - c0 == 1: step[(x1 - x0, y1 - y0)] += 1
        report["consecutive_C_tile_step_top"] = [(f"dx={k[0]} dy={k[1]}", v) for k, v in step.most_common(8)]
        # linearni fit C = a*tx + b*ty + k ?
        xs = [p[1] for p in pts]; ys = [p[2] for p in pts]; cs = [p[0] for p in pts]
        report["tile_x_range"] = [min(xs), max(xs)]; report["tile_y_range"] = [min(ys), max(ys)]
        # Morton proba
        mb = Counter()
        for bits in (8, 10, 12, 14, 16):
            for (name, fn) in (("xy", lambda x, y: morton(x, y, bits)), ("yx", lambda x, y: morton(y, x, bits))):
                # da li je C - C0 == morton - morton0 za susedne?
                ok = 0
                base_c, base_m = cs[0], fn(xs[0], ys[0])
                for c, x, y in zip(cs, xs, ys):
                    if c - base_c == fn(x, y) - base_m: ok += 1
                mb[f"morton {name} {bits}b"] = ok
        report["C_morton_consistency"] = mb.most_common(4)
        # row-major proba: C = C0 + (ty-ty0)*nx + (tx-tx0)
        best = None
        for nx in range(1, 4097):
            ok = sum(1 for c, x, y in zip(cs, xs, ys) if c - cs[0] == (y - ys[0]) * nx + (x - xs[0]))
            if best is None or ok > best[1]: best = (nx, ok)
        report["C_rowmajor_best"] = {"nx": best[0], "matches": best[1], "of": len(cs)}
        best = None
        for ny in range(1, 4097):
            ok = sum(1 for c, x, y in zip(cs, xs, ys) if c - cs[0] == (x - xs[0]) * ny + (y - ys[0]))
            if best is None or ok > best[1]: best = (ny, ok)
        report["C_colmajor_best"] = {"ny": best[0], "matches": best[1], "of": len(cs)}
        report["tile_samples"] = [{"C": hex(c), "tx": x, "ty": y, **{k: v for k, v in tiles[c].items()}} for c, x, y in pts[:8]]

    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    with (output / "tiles.jsonl").open("w") as s:
        for c, t in sorted(tiles.items()):
            s.write(json.dumps({"C": c, "blocks": len(per_tile[c]), **t}, separators=(",", ":")) + "\n")
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("graph_blocks", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    print(json.dumps(run(a.graph_blocks, a.output), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
