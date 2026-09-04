#!/usr/bin/env python3
"""orion_cells_geojson.py — celije blokova kao GeoJSON pravougaonici.

Ulaz je `graph_blocks.jsonl` iz `orion_block_key_spatial_probe.py`.  Za
svaki blok crta se celija izracunata iz (A, x0, y0) — dakle ono sto kljuc
tvrdi — i bbox stvarnih tacaka.  Sluzi za vizuelno poredjenje originalnog
i generisanog ATLAS-a nad istim podrucjem.  Koordinate su `degree x 1e7`
podeljene sa 1e7, bez ikakvog pomaka.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_tile_formula_verify import cell_origin  # noqa: E402


def rect(x0, y0, x1, y1):
    s = 1e7
    return [[[x0 / s, y0 / s], [x1 / s, y0 / s], [x1 / s, y1 / s], [x0 / s, y1 / s], [x0 / s, y0 / s]]]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("graph_blocks", type=Path); ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--bbox", type=float, nargs=4, metavar=("LON0", "LAT0", "LON1", "LAT1"))
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    feats = []
    for line in a.graph_blocks.open():
        r = json.loads(line)
        x0, y0, p, q = cell_origin(r)
        if a.bbox:
            if r["lon1"] / 1e7 < a.bbox[0] or r["lon0"] / 1e7 > a.bbox[2] or r["lat1"] / 1e7 < a.bbox[1] or r["lat0"] / 1e7 > a.bbox[3]:
                continue
        feats.append({"type": "Feature", "properties": {"kind": "cell", "A": r["A"], "n": r["n"], "src": a.label, "K": hex(r["K"])},
                      "geometry": {"type": "Polygon", "coordinates": rect(x0, y0, x0 + (1 << p), y0 + (1 << q))}})
        feats.append({"type": "Feature", "properties": {"kind": "bbox", "A": r["A"], "src": a.label},
                      "geometry": {"type": "Polygon", "coordinates": rect(r["lon0"], r["lat0"], r["lon1"], r["lat1"])}})
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps({"type": "FeatureCollection", "features": feats}))
    print(f"{a.label}: {len(feats) // 2} blokova -> {a.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
