#!/usr/bin/env python3
"""
atlas_export.py — izvoz tačaka iz `.ATLAS` (PSD) u GeoJSON.

Sklapa sve što je utvrđeno:
  1. blokovi se šetaju preko polja `Size` na `+0x10`
  2. telo bloka je LZMA1 raw (tip 3), tabela delova na `+0x22`
  3. u raspakovanom delu: katalog imena, pa `02 <tip> <velicina> 01` zapisi
  4. podaci idu SEKVENCIJALNO od baze; baza se traži po bloku
  5. kolone 0,1,2 = PointLlh; 3,4,5 = PointLld
     kolona 0 = dužina + POMAK, kolona 1 = širina, obe `int32` skale 1e-7

Pomak je utvrđen merenjem kao ≈80° (Kopenhagen i Harkov se poklapaju).
Menja se preko `--bias` da bi se preklapanjem sa pravom podlogom doterao.

Komande:
  export <atlas> --out t.geojson [--lat0 55.5 --lat1 56.2] [--bias 80.0]
  list   <atlas> --limit 20        pregled tajlova i njihovih opsega
"""

import argparse
import json
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from atlas_blocks import read_lp, parse_chunks, decompress_chunk, TILE_SPAN

COORD = 1e7
TYPES_OK = (0x23, 0x24, 0x25, 0x34, 0x35, 0x37, 0x45)


def iter_blocks(path, limit=10 ** 7):
    size = os.path.getsize(path)
    f = open(path, "rb")
    off, n = 0, 0
    while n < limit:
        f.seek(off)
        h = f.read(0x20)
        if len(h) < 0x20:
            break
        nm, _ = read_lp(h, 0)
        (bs,) = struct.unpack_from("<I", h, 0x10)
        if nm is None or bs == 0 or off + bs > size:
            break
        f.seek(off)
        yield off, f.read(bs)
        off += bs
        n += 1
    f.close()


def chunk_of(blk):
    info = parse_chunks(blk)
    if not info:
        return None
    kind, prs, doff = info
    if prs[0][0] == 0:
        return None
    try:
        return decompress_chunk(kind, blk[doff:], prs[0][1])[:prs[0][1]]
    except Exception:
        return None


def schema_of(d):
    types, last = [], 0
    for m in re.finditer(rb"\x02(.)(....)\x01", d, re.S):
        t = m.group(1)[0]
        (sz,) = struct.unpack("<I", m.group(2))
        if t in TYPES_OK and sz < len(d):
            types.append((t, sz))
            last = m.end()
    return types, last


LAT_CELL = 1 << 18          # 0.0262144 st
LON_CELL = 1 << 19          # 0.0524288 st — dužinske celije su 2x sire


def find_base(d, types, last, strict=True):
    """Traži bazu tako da OBE koordinatne kolone legnu u svoju ćeliju.

    Ranija verzija je proveravala samo kolonu 1 i tražila da bude u opsegu
    24..79° — time je sama sebi nametala koja je kolona širina i primala
    lažne pogotke. Stroga verzija koristi geometriju mreže, koja je
    nezavisno utvrđena: dužina se drži ćelije `2^19`, širina ćelije `2^18`,
    i obe moraju da leže unutar ćelije poravnate na nulu.
    """
    if len(types) < 3 or types[0][0] != 0x35 or types[1][0] != 0x35:
        return None
    sz = types[0][1]
    if sz < 64 or types[1][1] != sz:
        return None
    n = min(24, sz // 4)
    for base in range(last, min(last + 300, len(d) - 2 * sz)):
        if base + sz + n * 4 > len(d):
            break
        a = struct.unpack_from("<" + "i" * n, d, base)          # dužina
        b = struct.unpack_from("<" + "i" * n, d, base + sz)     # širina
        if min(a) <= 0 or min(b) <= 0:
            continue
        if max(a) - min(a) > LON_CELL or max(b) - min(b) > LAT_CELL:
            continue
        if not strict:
            return base
        # obe kolone moraju ležati unutar JEDNE ćelije poravnate na nulu
        if min(a) // LON_CELL != max(a) // LON_CELL:
            continue
        if min(b) // LAT_CELL != max(b) // LAT_CELL:
            continue
        return base
    return None


def read_triple(d, base, types, first, bias_units):
    """Pročitaj (dužina, širina, visina) za trojku koja počinje kolonom `first`."""
    if first + 2 >= len(types):
        return []
    pos = base + sum(sz for _, sz in types[:first])
    t_lon, sz_lon = types[first]
    t_lat, sz_lat = types[first + 1]
    t_h, sz_h = types[first + 2]
    if t_lon != 0x35 or t_lat != 0x35 or sz_lon != sz_lat or sz_lon < 4:
        return []
    cnt = sz_lon // 4
    if pos + sz_lon + sz_lat > len(d):
        return []
    lons = struct.unpack_from("<" + "i" * cnt, d, pos)
    lats = struct.unpack_from("<" + "i" * cnt, d, pos + sz_lon)
    hs = ()
    hpos = pos + sz_lon + sz_lat
    if sz_h and hpos + sz_h <= len(d) and sz_h // 2 >= cnt:
        hs = struct.unpack_from("<" + "H" * cnt, d, hpos)
    out = []
    for i in range(cnt):
        out.append(((lons[i] - bias_units) / COORD, lats[i] / COORD,
                    hs[i] if i < len(hs) else None))
    return out


def collect(path, bias, lat0, lat1, lon0, lon1, limit_blocks):
    bias_units = int(round(bias * COORD))
    feats, tiles = [], 0
    for boff, blk in iter_blocks(path, limit_blocks):
        d = chunk_of(blk)
        if d is None:
            continue
        types, last = schema_of(d)
        base = find_base(d, types, last)
        if base is None:
            continue
        pts = read_triple(d, base, types, 0, bias_units) + \
              read_triple(d, base, types, 3, bias_units)
        keep = [p for p in pts
                if lat0 <= p[1] <= lat1 and lon0 <= p[0] <= lon1]
        if not keep:
            continue
        tiles += 1
        for lon, lat, h in keep:
            props = {"blok": f"0x{boff:x}"}
            if h is not None:
                props["h"] = h
            feats.append({"type": "Feature",
                          "geometry": {"type": "Point",
                                       "coordinates": [round(lon, 7), round(lat, 7)]},
                          "properties": props})
    return feats, tiles


def cmd_export(args):
    feats, tiles = collect(args.file, args.bias, args.lat0, args.lat1,
                           args.lon0, args.lon1, args.limit)
    fc = {"type": "FeatureCollection", "features": feats}
    with open(args.out, "w") as f:
        json.dump(fc, f)
    print(f"# tajlova sa pogotkom: {tiles}, tačaka: {len(feats)}")
    if feats:
        lons = [f["geometry"]["coordinates"][0] for f in feats]
        lats = [f["geometry"]["coordinates"][1] for f in feats]
        print(f"  opseg: lon {min(lons):.5f} .. {max(lons):.5f}   "
              f"lat {min(lats):.5f} .. {max(lats):.5f}")
    print(f"  upisano u {args.out}  ({os.path.getsize(args.out)} B)")
    print("  otvoriti na geojson.io ili u QGIS-u preko prave podloge")


def cmd_list(args):
    n = 0
    for boff, blk in iter_blocks(args.file, args.limit_blocks):
        d = chunk_of(blk)
        if d is None:
            continue
        types, last = schema_of(d)
        base = find_base(d, types, last)
        if base is None:
            continue
        pts = read_triple(d, base, types, 0, int(round(args.bias * COORD)))
        if not pts:
            continue
        lons = [p[0] for p in pts]
        lats = [p[1] for p in pts]
        print(f"0x{boff:08x}  n={len(pts):5d}  lon {min(lons):8.4f}..{max(lons):8.4f}  "
              f"lat {min(lats):8.4f}..{max(lats):8.4f}")
        n += 1
        if n >= args.limit:
            break


def main():
    p = argparse.ArgumentParser(description="Izvoz .ATLAS tačaka u GeoJSON")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("export", cmd_export), ("list", cmd_list)):
        sp = sub.add_parser(name)
        sp.add_argument("file")
        sp.add_argument("--bias", type=float, default=80.0)
        sp.add_argument("--limit-blocks", type=int, default=100000)
        if name == "export":
            sp.add_argument("--out", required=True)
            sp.add_argument("--lat0", type=float, default=-90)
            sp.add_argument("--lat1", type=float, default=90)
            sp.add_argument("--lon0", type=float, default=-180)
            sp.add_argument("--lon1", type=float, default=180)
            sp.add_argument("--limit", type=int, default=100000)
        else:
            sp.add_argument("--limit", type=int, default=20)
        sp.set_defaults(func=fn)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
