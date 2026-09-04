#!/usr/bin/env python3
"""orion_cell_chunk_writer.py — CONTAINER blok po celiji iz MIB izvora.

Za svaku celiju iz `orion_cell_partition.py`:
  1. iz punih MIB izvora (nodes/edges/clothoid JSONL) izdvoji redove
     cije ID-jeve celija sadrzi — jednim prolazom kroz svaki fajl;
  2. postojecim `build_merged_graph_chunk` napravi dekodirani chunk
     (cvor van celije postaje sentinel 0 u From/To, kao u originalu);
  3. proveri politiku 64 KiB; celija koja je prelazi se prijavljuje kao
     `needs_split` i ne pise se;
  4. LZMA1 raw (lc3 lp0 pb2 dict 1 MiB) i CONTAINER blok po
     `docs/ATLAS_CONTAINER.md`: verzija 5.1.0, A, K -> (+0x1a, +0x1c),
     codec 3, tri chunk stavke, popuna, terminator.

Izlaz: `blocks/<K>.bin`, `blocks.jsonl` (K, A, size, usize, path, cell),
`report.json`, checksumovi.  Blokovi su uredjeni po K.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_block_writer import TERMINATOR, align16  # noqa: E402
from orion_tile_formula_verify import block_key  # noqa: E402
from orion_cell_partition import MIN_A  # noqa: E402
from orion_centerline_writer import read_centerline_sources  # noqa: E402
from orion_merged_graph_writer import build_merged_graph_chunk  # noqa: E402
from orion_object_writer import read_edge_reference_sources, read_point_llh_rows  # noqa: E402
from orion_cell_partition import exponents as _exp  # noqa: E402

MAX_USIZE = 65536
FILT = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 20}]
VERSION = bytes([5, 1, 0, 0])


def container_block(A: int, K: int, decoded: bytes) -> bytes:
    comp = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=FILT)
    payload = comp.compress(decoded) + comp.flush()
    name = b"CONTAINER"
    out = bytearray([len(name)]) + name + b"\xcb" * (0x10 - 1 - len(name))
    out += struct.pack("<I", 0) + VERSION
    out += struct.pack("<HHI", A, (K & 0xFF) << 8, K >> 8)
    out.append(3); out.append(3)
    out += struct.pack("<II", len(payload), len(decoded)) + struct.pack("<II", 0, 0) * 2
    out += payload
    size = align16(len(out) + 16)
    out += b"\xcc" * (size - 16 - len(out)) + TERMINATOR
    struct.pack_into("<I", out, 0x10, size)
    return bytes(out)


def filter_jsonl(src: Path, dst: Path, key: str, wanted: set[int]) -> int:
    n = 0
    with src.open("r", encoding="utf-8") as s, dst.open("w", encoding="utf-8") as d:
        for line in s:
            # brz predfilter bez parsiranja: id se javlja kao "key":N
            i = line.find(f'"{key}":')
            if i < 0:
                continue
            j = i + len(key) + 3
            while j < len(line) and line[j] == " ":
                j += 1
            k = j
            while k < len(line) and line[k].isdigit():
                k += 1
            try:
                if int(line[j:k]) not in wanted:
                    continue
            except ValueError:
                continue
            # potvrda na top-level polju, da ugnjezdeni id ne prodje
            if int(json.loads(line)[key]) in wanted:
                d.write(line); n += 1
    return n



def _emit_block(A, x0, y0, n_rows, e_rows, cl_rows, output, rows, ci):
    decoded, _, _, details = build_merged_graph_chunk(n_rows, e_rows, cl_rows)
    if len(decoded) > MAX_USIZE:
        return len(decoded)
    K = block_key(A, x0, y0)
    block = container_block(A, K, decoded)
    path = output / "blocks" / f"{K:010x}.bin"
    path.write_bytes(block)
    rows.append({"K": K, "A": A, "size": len(block), "usize": len(decoded),
                 "path": str(path), "cell": ci, "nodes": len(n_rows), "edges": len(e_rows)})
    return 0


def emit_cell(A, x0, y0, n_rows, e_rows, cl_rows, edge_centroid, node_pos,
              output, rows, needs_split, ci):
    """Emit blok; ako prelazi 64 KiB, deli celiju dublje po istoj geometriji.

    Deli se po **cvorovima** (blok mora imati bar jedan `PointLlh` red, a
    bbox bloka se racuna iz cvorova).  Edge prati svoj pocetni cvor, pa
    krajnji; edge bez ijednog lokalnog cvora ostaje u tekucoj celiji.
    """
    over = _emit_block(A, x0, y0, n_rows, e_rows, cl_rows, output, rows, ci)
    if not over:
        return
    if A <= MIN_A or len(n_rows) < 2:
        needs_split.append({"cell": ci, "A": A, "usize": over, "edges": len(e_rows),
                            "nodes": len(n_rows), "reason": "nema dalje podele"})
        return
    child_A = A - 1
    p, q = _exp(child_A)
    cl_by_edge = {r["source_edge_id"]: r for r in cl_rows}
    nmap = {n["source_id"]: n for n in n_rows}
    groups: dict[tuple[int, int], dict] = {}
    node_group: dict[int, tuple[int, int]] = {}
    for nid, n in nmap.items():
        nx, ny = node_pos[nid]
        key = ((nx >> p) << p, (ny >> q) << q)
        groups.setdefault(key, {"edges": [], "nodes": []})["nodes"].append(n)
        node_group[nid] = key
    orphan = []
    for e in e_rows:
        key = node_group.get(e["from_source_node_id"]) or node_group.get(e["to_source_node_id"])
        if key is None:
            orphan.append(e)
        else:
            groups[key]["edges"].append(e)
    if orphan:
        # edge bez lokalnog cvora: pridruzi najvecoj deci, da se ne izgubi
        biggest = max(groups, key=lambda k: len(groups[k]["nodes"]))
        groups[biggest]["edges"].extend(orphan)
    groups = {k: g for k, g in groups.items() if g["edges"]}
    if not groups:
        needs_split.append({"cell": ci, "A": A, "usize": over, "edges": len(e_rows),
                            "nodes": len(n_rows), "reason": "nijedan edge nema cvor"})
        return
    if len(groups) == 1 and len(next(iter(groups.values()))["edges"]) == len(e_rows):
        (cx0, cy0), g = next(iter(groups.items()))
        emit_cell(child_A, cx0, cy0, g["nodes"], g["edges"],
                  [cl_by_edge[e["source_edge_id"]] for e in g["edges"] if e["source_edge_id"] in cl_by_edge],
                  edge_centroid, node_pos, output, rows, needs_split, ci)
        return
    for (cx0, cy0), g in sorted(groups.items()):
        emit_cell(child_A, cx0, cy0, g["nodes"], g["edges"],
                  [cl_by_edge[e["source_edge_id"]] for e in g["edges"] if e["source_edge_id"] in cl_by_edge],
                  edge_centroid, node_pos, output, rows, needs_split, ci)


def run(cells_path: Path, nodes: Path, edges: Path, clothoids: Path, output: Path, cell_limit: int) -> dict[str, object]:
    cells = [json.loads(l) for l in cells_path.open()]
    if cell_limit:
        cells = cells[:cell_limit]
    node_ids = {n for c in cells for n in c["node_ids"]}
    edge_ids = {e for c in cells for e in c["edge_ids"]}
    output.mkdir(parents=True, exist_ok=True)
    (output / "blocks").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        print(f"  filtriram {len(node_ids)} cvorova, {len(edge_ids)} edge-ova iz izvora...", flush=True)
        nn = filter_jsonl(nodes, tmp / "nodes.jsonl", "node_id", node_ids)
        ne = filter_jsonl(edges, tmp / "edges.jsonl", "edge_id", edge_ids)
        nc = filter_jsonl(clothoids, tmp / "clothoids.jsonl", "edge_id", edge_ids)
        # edge bez ijednog clothoid segmenta (degenerisana geometrija) ne moze
        # u centerline sloj; izbacuje se iz celije i broji
        dropped = set()
        kept_lines = []
        for line in (tmp / "clothoids.jsonl").open("r", encoding="utf-8"):
            rec = json.loads(line)
            if rec.get("segments"):
                kept_lines.append(line)
            else:
                dropped.add(int(rec["edge_id"]))
        (tmp / "clothoids.jsonl").write_text("".join(kept_lines), encoding="utf-8")
        if dropped:
            edge_ids -= dropped
            for c in cells:
                c["edge_ids"] = [e for e in c["edge_ids"] if e not in dropped]
        print(f"  nadjeno cvorova={nn} edge-ova={ne} clothoida={nc} bez_segmenata={len(dropped)}", flush=True)
        all_nodes = {r["source_id"]: r for r in read_point_llh_rows(tmp / "nodes.jsonl")}
        all_edges = {r["source_edge_id"]: r for r in read_edge_reference_sources(tmp / "edges.jsonl")}
        all_cl = {int(r["source_edge_id"]): r for r in read_centerline_sources(tmp / "clothoids.jsonl")}
    # centroid edge-a i pozicija cvora u orion jedinicama, iz vec ucitanih izvora
    node_pos = {i: (r["longitude"], r["latitude"]) for i, r in all_nodes.items()}
    edge_centroid = {}
    for eid, e in all_edges.items():
        f = node_pos.get(e["from_source_node_id"]); t = node_pos.get(e["to_source_node_id"])
        pts = [p for p in (f, t) if p]
        if pts:
            edge_centroid[eid] = (sum(p[0] for p in pts) // len(pts), sum(p[1] for p in pts) // len(pts))
        else:
            edge_centroid[eid] = (0, 0)
    rows = []; needs_split = []; skipped = []
    for ci, c in enumerate(cells):
        n_rows = [all_nodes[i] for i in c["node_ids"] if i in all_nodes]
        e_rows = [all_edges[i] for i in c["edge_ids"] if i in all_edges]
        cl_rows = [all_cl[i] for i in c["edge_ids"] if i in all_cl]
        if not e_rows or not n_rows:
            skipped.append({"cell": ci, "reason": "bez cvorova ili edge-ova", "nodes": len(n_rows), "edges": len(e_rows)})
            continue
        emit_cell(c["A"], c["x0"], c["y0"], n_rows, e_rows, cl_rows, edge_centroid,
                  node_pos, output, rows, needs_split, ci)
        if (ci + 1) % 50 == 0:
            print(f"  ...{ci + 1}/{len(cells)} celija", flush=True)
    rows.sort(key=lambda r: r["K"])
    with (output / "blocks.jsonl").open("w") as s:
        for r in rows:
            s.write(json.dumps(r, separators=(",", ":")) + "\n")
    report = {"cells": len(cells), "blocks_written": len(rows), "edges_dropped_no_segments": len(dropped),
              "needs_split": needs_split[:50],
              "needs_split_count": len(needs_split), "skipped": skipped[:20], "skipped_count": len(skipped),
              "usize_max": max((r["usize"] for r in rows), default=0),
              "total_block_bytes": sum(r["size"] for r in rows),
              "keys_strictly_increasing": all(rows[i]["K"] < rows[i + 1]["K"] for i in range(len(rows) - 1))}
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cells", type=Path)
    ap.add_argument("--nodes", type=Path, required=True); ap.add_argument("--edges", type=Path, required=True)
    ap.add_argument("--clothoids", type=Path, required=True); ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--cell-limit", type=int, default=0)
    a = ap.parse_args()
    print(json.dumps(run(a.cells, a.nodes, a.edges, a.clothoids, a.output, a.cell_limit), indent=2, ensure_ascii=False)); return 0


if __name__ == "__main__":
    sys.exit(main())
