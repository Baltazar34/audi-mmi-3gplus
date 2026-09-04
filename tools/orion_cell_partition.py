#!/usr/bin/env python3
"""orion_cell_partition.py — particionisanje MIB grafa u celije Orion stabla.

Koristi dokazanu geometriju kljuca (`docs/ATLAS_CONTAINER.md`): globalno
binarno stablo nad `degree x 1e7`, naizmenicne ose, nivo `A` sa celijom
`2^((A+17)//2) x 2^((A+16)//2)`, najfinije `A = 18`.  Iz originala je
izmereno da se celija deli dok dekodirani chunk ne stane u 64 KiB.

Ovde se deli po broju edge-ova (`--max-edges`) kao zamena za velicinu
chunka, jer stvarna velicina zavisi od writera; prag se kalibrise iz
originala (~580 edge-ova u chunku od 50 KB).  Posle generisanja chunka
`orion_cell_chunk_writer` ce proveriti stvarnu velicinu i, ako treba,
podeliti dalje.

Deli se po **cvorovima**, jer blok mora imati bar jedan `PointLlh` red i
zato sto se bbox bloka racuna iz cvorova.  Edge pripada celiji svog
pocetnog cvora (pa krajnjeg, ako pocetni nije lokalan).  Cvor druge celije
ostaje "eksterni" i dobija Orion sentinel 0 u `From`/`To`, kao u originalu.

Izlaz: `cells.jsonl` (A, x0, y0, K, node_ids, edge_ids), `report.json`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_tile_formula_verify import block_key, exponents  # noqa: E402

MIN_A = 18
MAX_A = 40
SCALE = 10_000_000


def to_units(lon: float, lat: float) -> tuple[int, int]:
    return round(lon * SCALE), round(lat * SCALE)


def cell_of(x: int, y: int, A: int) -> tuple[int, int]:
    p, q = exponents(A)
    return (x >> p) << p, (y >> q) << q


def split(cell: tuple[int, int, int], items: list[tuple[int, int, object]],
          max_items: int, out: list[dict[str, object]]) -> None:
    """cell = (A, x0, y0); items = (x, y, id)."""
    A, x0, y0 = cell
    if len(items) <= max_items or A <= MIN_A:
        out.append({"A": A, "x0": x0, "y0": y0, "items": [i for _, _, i in items]})
        return
    child_A = A - 1
    p, q = exponents(child_A)
    groups: dict[tuple[int, int], list] = {}
    for x, y, i in items:
        groups.setdefault(((x >> p) << p, (y >> q) << q), []).append((x, y, i))
    if len(groups) == 1:
        # sve u istoj deci: nastavi dublje bez grananja
        (cx, cy), only = next(iter(groups.items()))
        split((child_A, cx, cy), only, max_items, out)
        return
    for (cx, cy), sub in sorted(groups.items()):
        split((child_A, cx, cy), sub, max_items, out)


def run(nodes_path: Path, edges_path: Path, output: Path, max_edges: int) -> dict[str, object]:
    nodes = {}
    for line in nodes_path.open():
        n = json.loads(line)
        lon, lat = n["coordinate"]["wgs84"]
        nodes[n["node_id"]] = to_units(lon, lat)
    edge_nodes = {}
    for line in edges_path.open():
        e = json.loads(line)
        edge_nodes[e["edge_id"]] = (e["from"]["node_id"], e["to"]["node_id"])
    if not edge_nodes:
        raise SystemExit("nema edge-ova")
    node_items = [(x, y, nid) for nid, (x, y) in nodes.items()]
    # koren: najmanja celija koja sadrzi sve cvorove
    xs = [x for x, _, _ in node_items]; ys = [y for _, y, _ in node_items]
    A = MIN_A
    while A < MAX_A:
        p, q = exponents(A)
        if (min(xs) >> p) == (max(xs) >> p) and (min(ys) >> q) == (max(ys) >> q):
            break
        A += 1
    root = (A, *cell_of(min(xs), min(ys), A))
    cells: list[dict[str, object]] = []
    split(root, node_items, max_edges, cells)
    node_cell = {}
    for ci, c in enumerate(cells):
        c["K"] = block_key(c["A"], c["x0"], c["y0"])
        c["node_ids"] = c.pop("items")
        c["edge_ids"] = []
        for nid in c["node_ids"]:
            node_cell[nid] = ci
    # edge ide u celiju svog pocetnog cvora; ako on nije poznat, krajnjeg
    unplaced_edges = 0
    for eid, (a_id, b_id) in edge_nodes.items():
        ci = node_cell.get(a_id, node_cell.get(b_id))
        if ci is None:
            unplaced_edges += 1
            continue
        cells[ci]["edge_ids"].append(eid)
    cells = [c for c in cells if c["edge_ids"]]
    internal = external = 0
    for ci, c in enumerate(cells):
        own = set(c["node_ids"])
        for eid in c["edge_ids"]:
            for nid in edge_nodes[eid]:
                if nid in own: internal += 1
                else: external += 1
    cells.sort(key=lambda c: c["K"])
    report = {"nodes": len(nodes), "edges": len(edge_nodes), "root": {"A": root[0], "x0": root[1], "y0": root[2]},
              "unplaced_edges": unplaced_edges,
              "cells": len(cells), "max_edges": max_edges,
              "A_histogram": dict(sorted(Counter(c["A"] for c in cells).items())),
              "edges_per_cell": {"min": min(len(c["edge_ids"]) for c in cells), "max": max(len(c["edge_ids"]) for c in cells)},
              "edge_endpoints_internal": internal, "edge_endpoints_external": external,
              "keys_strictly_increasing": all(cells[i]["K"] < cells[i + 1]["K"] for i in range(len(cells) - 1)),
              "nodes_per_cell": {"min": min(len(c["node_ids"]) for c in cells), "max": max(len(c["node_ids"]) for c in cells)}}
    output.mkdir(parents=True, exist_ok=True)
    with (output / "cells.jsonl").open("w") as s:
        for c in cells:
            s.write(json.dumps(c, separators=(",", ":")) + "\n")
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("nodes", type=Path); ap.add_argument("edges", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--max-edges", type=int, default=300, help="prag broja cvorova po celiji")
    a = ap.parse_args()
    print(json.dumps(run(a.nodes, a.edges, a.output, a.max_edges), indent=2, ensure_ascii=False)); return 0


if __name__ == "__main__":
    sys.exit(main())
