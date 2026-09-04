#!/usr/bin/env python3
"""
atlas_blocks.py — parser blok-strukture .ATLAS (Orion) kontejnera.

Otkriveno na TER2 iz izdanja 6.36.0:
  - fajl je niz blokova; svaki blok se ZAVRSAVA 16-bajtnim magic-om
    01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10  (MD5/SHA IV konstante)
  - blok POCINJE length-prefixed imenom (npr. 06 "HEADER", 09 "CONTAINER"),
    dopunjenim 0xCC do granice
  - unutar bloka:
      01 <len> <ime> <tip> <flag>    definicija kolone; flag 0x00 u korenu, 0x01 u listu
      02 <tip> <sirina:u32> 01       tip i sirina kolone u bajtovima
    pa niz zastavica, pa spakovan red sirine sum(sirina)

  Imena se NE zipuju slepo sa tipovima: koren ide 1:1, a list mreze 1:2 —
  po imenovanoj koloni idu dva `02` zapisa, (u32 velicina, u24 pokazivac).

Komande:
  scan   <fajl> [--limit N]   inventar blokova
  block  <fajl> --index N     sema jednog bloka
  decode <fajl> --index N     dekodiran red vrednosti + bbox i rezolucija
"""

import argparse
import os
import re
import struct

MAGIC = bytes.fromhex("0123456789abcdeffedcba9876543210")
TYPE_NAMES = {
    0x23: "u8?",  0x24: "u24?", 0x25: "u32", 0x34: "u24",
    0x35: "coord", 0x37: "str?", 0x45: "float",
}


def find_blocks(data, base=0):
    """Vrati [(start, end)] gde end pokazuje iza magic-a."""
    out = []
    prev = 0
    for m in re.finditer(re.escape(MAGIC), data):
        out.append((base + prev, base + m.end()))
        prev = m.end()
    return out


def block_name(blk):
    n = blk[0]
    if 1 <= n <= 32 and all(32 <= b < 127 for b in blk[1:1 + n]):
        return blk[1:1 + n].decode()
    return None


def parse_records(blk):
    """Zapis kolone je `01 <len> <ime> <tip> <flag>`, gde je flag 0x00 ili 0x01.

    Korenski blokovi koriste 0x00, listovi 0x01 — zato je provera na oba.
    """
    cols, types = [], []
    for m in re.finditer(rb"\x01([\x02-\x20])([ -~]{2,32})", blk):
        ln = m.group(1)[0]
        raw = m.group(2)
        if len(raw) < ln:
            continue
        name = raw[:ln]
        rest = blk[m.start() + 2 + ln:m.start() + 4 + ln]
        if len(rest) >= 2 and 32 <= rest[0] < 127 and rest[1] in (0x00, 0x01):
            cols.append((name.decode(), rest[0]))
    for m in re.finditer(rb"\x02(.)(....)\x01", blk, re.S):
        t = m.group(1)[0]
        (w,) = struct.unpack("<I", m.group(2))
        types.append((t, w))
    return cols, types


def align_cols(cols, types):
    """Poravnaj imena kolona na listu tipova.

    Blok pored kolona nosi i deskriptorske `01` zapise (npr. SoarTerrain),
    pa se imena ne smeju slepo zipovati sa tipovima. Dva slucaja:
      1:1  — trazi se prozor imena ciji se niz tipova poklapa sa `02` zapisima
      1:2  — list mreze: po imenovanoj koloni idu DVA `02` zapisa,
             (u32 velicina, u24 pokazivac); ime nosi drugi iz para
    Vraca (lista_imena, rezim) ili (None, None) ako se ne poklapa.
    """
    if not types:
        return None, None
    sig = [t for t, _ in types]

    if len(cols) >= len(types):
        for i in range(len(cols) - len(types) + 1):
            if [t for _, t in cols[i:i + len(types)]] == sig:
                return [nm for nm, _ in cols[i:i + len(types)]], "1:1"

    if len(cols) * 2 == len(types):
        if all(cols[i][1] == sig[2 * i + 1] for i in range(len(cols))):
            out = []
            for nm, _ in cols:
                out += [f"{nm}.size", f"{nm}.ptr"]
            return out, "1:2 (velicina + pokazivac)"

    return None, None


def resolve_cols(cols, types, blocks, data, win_base, upto):
    """Ako blok nema dovoljno imena, nasledi ih od ranijeg bloka sa istim
    potpisom tipova. Sema se definise jednom, listovi je referenciraju."""
    if len(cols) >= len(types) or not types:
        return cols, None
    sig = [t for t, _ in types]
    for j in range(upto - 1, -1, -1):
        s, e = blocks[j]
        prev = data[s - win_base:e - win_base]
        pcols, ptypes = parse_records(prev)
        if [t for t, _ in ptypes] == sig and len(pcols) >= len(types):
            return pcols, j
    # slabiji pokusaj: poklapanje po tipu kolone, redom
    for j in range(upto - 1, -1, -1):
        s, e = blocks[j]
        prev = data[s - win_base:e - win_base]
        pcols, _ = parse_records(prev)
        if len(pcols) >= len(types):
            by_type = {}
            for nm, t in pcols:
                by_type.setdefault(t, []).append(nm)
            out = []
            ok = True
            for t, _ in types:
                if by_type.get(t):
                    out.append((by_type[t].pop(0), t))
                else:
                    ok = False
                    break
            if ok:
                return out, j
    return cols, None


def cmd_scan(args):
    size = os.path.getsize(args.file)
    win = min(args.window, size)
    with open(args.file, "rb") as f:
        f.seek(size - win)
        data = f.read(win)
    blocks = find_blocks(data, base=size - win)
    print(f"# {os.path.basename(args.file)}  ({size} B), gledam poslednjih {win} B")
    print(f"# pronadjeno blokova: {len(blocks)}\n")
    counts = {}
    for i, (s, e) in enumerate(blocks[:args.limit]):
        blk = data[s - (size - win):e - (size - win)]
        nm = block_name(blk) or "<bez imena>"
        cols, types = parse_records(blk)
        counts[nm] = counts.get(nm, 0) + 1
        print(f"  [{i:4d}] 0x{s:08x}-0x{e:08x}  {e - s:6d} B  {nm:12s} "
              f"kolona={len(cols):2d} tipova={len(types):2d}")
    print("\n# ucestalost imena blokova (u prikazanom uzorku)")
    for nm, c in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {nm:16s} {c}")


COORD_SCALE = 1e7          # int32 stepeni x 10^7 (dokazano na TER2: -12.0 i 79.0 okrugli)


def decode_value(tcode, raw):
    """Vrati (prikaz, sirova_vrednost) za jednu celiju."""
    if not raw:
        return "<prazno>", None
    if tcode == 0x45 and len(raw) == 4:                      # float
        v = struct.unpack("<f", raw)[0]
        return f"{v}", v
    if tcode == 0x35 and len(raw) == 4:                      # koordinata
        v = struct.unpack("<i", raw)[0]
        return f"{v / COORD_SCALE:.7f}°  (sirovo {v})", v
    v = int.from_bytes(raw, "little")
    return f"{v}", v


def read_lp(d, off, maxlen=32):
    """Length-prefixed string: bajt duzine pa tekst."""
    n = d[off]
    if 1 <= n <= maxlen:
        raw = d[off + 1:off + 1 + n]
        if all(32 <= b < 127 for b in raw):
            return raw.decode(), n
    return None, n


def cmd_header(args):
    """Parsiraj SOrionDatabaseHeader_4_1 tacno onako kako ga validira
    COrionDatabase::create (NavCore FUN_08322504)."""
    size = os.path.getsize(args.file)
    d = open(args.file, "rb").read(0x60)

    ident, ilen = read_lp(d, 0x00)
    (hsize,) = struct.unpack_from("<I", d, 0x10)
    vmaj, vmin = d[0x14], d[0x15]
    (vpatch,) = struct.unpack_from("<H", d, 0x16)
    endian = chr(d[0x18])
    engine, elen = read_lp(d, 0x20)
    name, nlen = read_lp(d, 0x30)

    print(f"# {os.path.basename(args.file)}  ({size} B)\n")
    print(f"  Identification   '{ident}'        (duzina {ilen} na +0x00, tekst na +0x01)")
    print(f"  Size             {hsize}            (+0x10)")
    print(f"  Version          {vmaj}.{vmin}.{vpatch}          (+0x14 major, +0x15 minor, +0x16 patch u16)")
    print(f"  Endian           '{endian}'              (+0x18)")
    print(f"  Engine           '{engine}'         (duzina na +0x20, tekst na +0x21)")
    print(f"  Ime baze         '{name}'         (+0x30)")
    variant = {1: "SOrionDatabaseHeader_1_1", 4: "SOrionDatabaseHeader_4_1",
               5: "verzija 5 (PSD); engine u NavCore je 5.1.3"}.get(vmaj, "nepoznato")
    print(f"  Varijanta        {variant}")

    print("\n  64-bitna polja:")
    for off, lbl in ((0x40, "timestamp"), (0x48, "ukupno svih delova"),
                     (0x50, "velicina ovog fajla"), (0x58, "velicina drugog dela")):
        (v,) = struct.unpack_from("<Q", d, off)
        mark = "  <== poklapa se" if off == 0x50 and v == size else ""
        print(f"    +0x{off:02x}  {v:>20d}   {lbl}{mark}")

    print("\n  provere kao u COrionDatabase::create:")
    checks = [
        ("Identification == 'HEADER'", ident == "HEADER"),
        ("Size == 4096", hsize == 4096),
        ("Version major in (1,4,5)", vmaj in (1, 4, 5)),
        ("Version minor <= 7", vmin <= 7),
        ("Endian == 'l'", endian == "l"),
        ("Engine == 'Orion'", engine == "Orion"),
        ("polje +0x50 == stvarna velicina", struct.unpack_from("<Q", d, 0x50)[0] == size),
    ]
    for lbl, ok in checks:
        print(f"    [{'OK ' if ok else 'PAD'}] {lbl}")
    if not all(ok for _, ok in checks):
        raise SystemExit(1)


def cmd_walk(args):
    """Prodji kroz lanac blokova preko polja Size na +0x10.

    Nije potrebno traziti magic: svaki blok nosi svoju velicinu, pa je
    sledeci blok na off + Size. HEADER ima Size 4096, pa prvi CONTAINER
    stoji tacno na 0x1000.
    """
    size = os.path.getsize(args.file)
    f = open(args.file, "rb")
    off, n = args.start, 0
    names, sizes, versions = {}, [], {}
    first_bad = None
    while n < args.limit:
        f.seek(off)
        d = f.read(0x20)
        if len(d) < 0x20:
            break
        nm, _ = read_lp(d, 0)
        (bsize,) = struct.unpack_from("<I", d, 0x10)
        ver = f"{d[0x14]}.{d[0x15]}.{struct.unpack_from('<H', d, 0x16)[0]}"
        if nm is None or bsize == 0 or off + bsize > size:
            first_bad = off
            break
        names[nm] = names.get(nm, 0) + 1
        versions[ver] = versions.get(ver, 0) + 1
        sizes.append(bsize)
        if args.verbose:
            print(f"0x{off:08x}  {nm:12s} {bsize:8d}  {ver}")
        off += bsize
        n += 1
    f.close()

    print(f"# {os.path.basename(args.file)}  ({size} B)")
    print(f"# blokova prosetano: {n}, zavrseno na 0x{off:08x} "
          f"({off / size * 100:.2f}% fajla)")
    if first_bad is not None:
        print(f"# lanac prekinut na 0x{first_bad:08x}")
    elif off == size:
        print("# lanac pokriva fajl TACNO do kraja")
    print("\n# imena blokova")
    for k, v in sorted(names.items(), key=lambda x: -x[1]):
        print(f"   {k:12s} {v}")
    print("\n# verzije")
    for k, v in sorted(versions.items(), key=lambda x: -x[1]):
        print(f"   {k:8s} {v}")
    if sizes:
        print(f"\n# velicine blokova: min={min(sizes)} max={max(sizes)} "
              f"prosek={sum(sizes) // len(sizes)}")


LZMA_FILTERS = [{"id": None, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 16}]


def decompress_chunk(kind, data, want=None):
    """Raspakuj jedan deo. Tip 3 = LZMA1 raw (lc=3 lp=0 pb=2, dict 64K),
    utvrdjeno empirijski na PSD3 i potvrdjeno poklapanjem velicine u bajt."""
    import lzma
    import zlib
    if kind == 3:
        f = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 16}]
        d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=f)
        return d.decompress(data, max_length=(want + 4096) if want else -1)
    if kind == 2:
        for wbits in (-15, 15):
            try:
                return zlib.decompressobj(wbits).decompress(data)
            except zlib.error:
                continue
    return None


def parse_chunks(blk):
    """Vrati (tip, [(csize, usize)], offset_podataka) ili None ako blok nije kompresovan."""
    if len(blk) < 0x24:
        return None
    kind, count = blk[0x20], blk[0x21]
    if kind not in (2, 3) or not (1 <= count <= 8):
        return None
    pairs = []
    for i in range(count):
        if 0x22 + i * 8 + 8 > len(blk):
            return None
        pairs.append(struct.unpack_from("<II", blk, 0x22 + i * 8))
    return kind, pairs, 0x22 + count * 8


def cmd_unpack(args):
    """Prodji blokove, raspakuj kompresovane i prijavi statistiku."""
    size = os.path.getsize(args.file)
    f = open(args.file, "rb")
    off = n = comp = ok = fail = 0
    tin = tout = 0
    kinds = {}
    out_f = open(args.out, "wb") if args.out else None
    while n < args.limit:
        f.seek(off)
        h = f.read(0x20)
        if len(h) < 0x20:
            break
        nm, _ = read_lp(h, 0)
        (bsize,) = struct.unpack_from("<I", h, 0x10)
        if nm is None or bsize == 0 or off + bsize > size:
            break
        f.seek(off)
        blk = f.read(bsize)
        info = parse_chunks(blk)
        if info:
            kind, pairs, doff = info
            comp += 1
            kinds[kind] = kinds.get(kind, 0) + 1
            pos = doff
            for csize, usize in pairs:
                if csize == 0:
                    continue
                try:
                    out = decompress_chunk(kind, blk[pos:], usize)
                except Exception:
                    out = None
                if out is not None and len(out) == usize:
                    ok += 1
                    tin += csize
                    tout += usize
                    if out_f:
                        out_f.write(out)
                else:
                    fail += 1
                pos += csize
        off += bsize
        n += 1
    f.close()
    if out_f:
        out_f.close()
    print(f"# {os.path.basename(args.file)}: {n} blokova, {comp} kompresovanih")
    print(f"  tipovi: " + ", ".join(f"{k}->{v}" for k, v in sorted(kinds.items())))
    print(f"  delova raspakovano: {ok}, neuspelih: {fail}")
    if tin:
        print(f"  {tin} -> {tout} B  (odnos {tout / tin:.2f}x)")
    if args.out:
        print(f"  upisano u {args.out}")


def cmd_records(args):
    """Parsiraj tagovan zapis iz RASPAKOVANOG sadrzaja (PSD i slicni).

    Oblik: <tag 01|02|03> <duzina> <ime> <payload>
      tag 02 / 03 : payload = u32 + u8
      tag 01      : payload = u16 + u32 + u8
    Prvi zapis (koren, npr. "Map") ima duzi payload.
    """
    d = open(args.file, "rb").read()
    print(f"# {os.path.basename(args.file)}  ({len(d)} B)\n")
    pat = re.compile(rb"([\x01-\x03])([\x02-\x1f])([ -~]{2,31})")
    seen = {}
    rows = []
    for m in pat.finditer(d):
        tag = m.group(1)[0]
        ln = m.group(2)[0]
        raw = m.group(3)
        if len(raw) < ln:
            continue
        name = raw[:ln]
        try:
            nm_try = name.decode("ascii")
        except UnicodeDecodeError:
            continue
        # odbaci lazne pogotke iz binarnog smeca: ime mora poceti slovom,
        # biti alfanumericko i sadrzati bar jedno malo slovo
        if not (nm_try[:1].isalpha() and nm_try.replace("_", "").isalnum()
                and any(c.islower() for c in nm_try)):
            continue
        pos = m.start() + 2 + ln
        if tag == 1:
            if pos + 7 > len(d):
                continue
            a = struct.unpack_from("<H", d, pos)[0]
            b = struct.unpack_from("<I", d, pos + 2)[0]
            c = d[pos + 6]
            payload = (a, b, c)
        else:
            if pos + 5 > len(d):
                continue
            b = struct.unpack_from("<I", d, pos)[0]
            c = d[pos + 4]
            payload = (None, b, c)
        nm = name.decode()
        seen[nm] = seen.get(nm, 0) + 1
        if len(rows) < args.limit:
            rows.append((m.start(), tag, nm, payload))

    print(f"{'offset':>10}  tag  {'ime':30s} {'A':>6} {'B':>10} {'C':>4}")
    for off, tag, nm, (a, b, c) in rows:
        astr = "-" if a is None else str(a)
        print(f"0x{off:08x}   {tag:02d}  {nm:30s} {astr:>6} {b:>10} {c:>4}")
    print(f"\n# razlicitih imena: {len(seen)}, ukupno zapisa: {sum(seen.values())}")
    print("# najcesca:")
    for k, v in sorted(seen.items(), key=lambda x: -x[1])[:15]:
        print(f"   {k:32s} {v}")


def cmd_geo(args):
    """Nadji nizove koordinata u RASPAKOVANOM sadrzaju.

    Pretpostavka preneta sa TER-a: int32, stepeni x 10^7. Trazi se par
    uzastopnih int32 koji oba padaju u opseg Evrope, pa se gleda da li
    takvi parovi cine niz sa konstantnim korakom (fiksna sirina zapisa).
    """
    d = open(args.file, "rb").read()
    LON = (int(args.lon_min * 1e7), int(args.lon_max * 1e7))
    LAT = (int(args.lat_min * 1e7), int(args.lat_max * 1e7))
    hits = []
    for off in range(0, len(d) - 8, args.align):
        a, b = struct.unpack_from("<ii", d, off)
        if LON[0] <= a <= LON[1] and LAT[0] <= b <= LAT[1]:
            hits.append((off, a, b, "lon,lat"))
        elif LAT[0] <= a <= LAT[1] and LON[0] <= b <= LON[1]:
            hits.append((off, a, b, "lat,lon"))
    print(f"# {os.path.basename(args.file)}  ({len(d)} B)")
    print(f"# kandidata za par koordinata: {len(hits)}\n")

    runs, cur = [], []
    for i in range(1, len(hits)):
        step = hits[i][0] - hits[i - 1][0]
        if step < args.min_step:
            continue
        if cur and step == cur[-1][1]:
            cur.append((hits[i], step))
        else:
            if len(cur) >= args.min_run:
                runs.append(cur)
            cur = [(hits[i], step)]
    if len(cur) >= args.min_run:
        runs.append(cur)
    runs.sort(key=len, reverse=True)

    print(f"# nizova sa konstantnim korakom (>= {args.min_run} clanova): {len(runs)}")
    for r in runs[:args.limit]:
        step = r[0][1]
        (off0, a0, b0, order) = r[0][0]
        (off1, a1, b1, _) = r[-1][0]
        print(f"\n  niz od {len(r) + 1} tacaka, korak {step} B, poredak {order}")
        print(f"    0x{off0:08x}  {a0 / 1e7:.7f}, {b0 / 1e7:.7f}")
        print(f"    0x{off1:08x}  {a1 / 1e7:.7f}, {b1 / 1e7:.7f}")
        for (off, a, b, o) in [x[0] for x in r[:args.show]]:
            print(f"      +0x{off:06x}  {a / 1e7:11.7f}  {b / 1e7:11.7f}")


LON_BIAS = 800_000_000        # kolona dužine nosi pomak od ~80° (potvrditi geodetski)
TILE_SPAN = 1 << 18           # raspon tajla u jedinicama 1e-7 stepena = 0.0262144°


def find_columns_np(path, min_len=200):
    """Brza detekcija kolona preko numpy-ja: grubo po grupama od 64, pa spajanje."""
    import numpy as np
    a = np.fromfile(path, dtype="<i4")
    g = 64
    m = (len(a) // g) * g
    b = a[:m].reshape(-1, g)
    span = b.max(axis=1).astype(np.int64) - b.min(axis=1).astype(np.int64)
    good = (span <= TILE_SPAN) & (b.min(axis=1) > 0)
    runs, i, n = [], 0, len(good)
    while i < n:
        if not good[i]:
            i += 1
            continue
        j = i
        while j < n and good[j]:
            j += 1
        # Spojeni region moze da premasi 2^18 jer sadrzi vise kolona.
        # Zato ga pohlepno delimo na maksimalne podnizove unutar jedne celije,
        # umesto da ga odbacimo u celini.
        seg = a[i * g:j * g]
        base = i * g
        k = 0
        while k < len(seg):
            lo = hi = int(seg[k])
            m = k + 1
            while m < len(seg):
                v = int(seg[m])
                lo2, hi2 = min(lo, v), max(hi, v)
                if hi2 - lo2 > TILE_SPAN:
                    break
                lo, hi = lo2, hi2
                m += 1
            if m - k >= min_len:
                runs.append(((base + k) * 4, m - k, lo, hi))
            k = m
        i = j
    return runs


def cmd_stats(args):
    """Globalni opseg SAMO detektovanih kolona — bez šuma od nasumičnih int32."""
    runs = find_columns_np(args.file, args.min_len)
    lat = [r for r in runs if 240000000 <= r[2] <= 790000000]
    oth = [r for r in runs if not (240000000 <= r[2] <= 790000000)]
    print(f"# {os.path.basename(args.file)}: {len(runs)} detektovanih kolona\n")
    for name, group in (("kolone u opsegu SIRINE (24..79)", lat),
                        ("ostale kolone", oth)):
        if not group:
            continue
        lo = min(r[2] for r in group)
        hi = max(r[3] for r in group)
        print(f"{name}: {len(group)} kolona")
        print(f"  globalni opseg: {lo / 1e7:.7f} .. {hi / 1e7:.7f}"
              f"   sirina {(hi - lo) / 1e7:.7f}°")
        res = {r[2] % TILE_SPAN for r in group}
        print(f"  razlicitih ostataka (min mod 2^18): {len(res)}"
              + (f"  -> {sorted(res)[:5]}" if len(res) <= 8 else ""))
        print()
    print("# poredjenje sa TER bounding box-om (iz sekcije 6.6):")
    print("   TER sirina : 24.3858334 .. 79.0000000   (54.6141666°)")
    print("   TER duzina : -12.0000000 .. 42.6141666  (54.6141666°)")


def cmd_tiles(args):
    """Nadji kolone koordinata u RASPAKOVANOM sadrzaju.

    Nalaz: kolone su obican `int32`, skala 1e7, slozene uzastopno u trojkama
    (dužina, širina, visina) iste dužine. Raspon jedne kolone je najviše
    2^18 jedinica = 0.0262144° — tajl je stepen dvojke.
    """
    d = open(args.file, "rb").read()
    n = len(d) // 4
    a = struct.unpack_from("<" + "i" * n, d, 0)
    runs, i = [], 0
    while i < n - args.min_len:
        seg = a[i:i + args.min_len]
        if min(seg) > 0 and max(seg) - min(seg) <= TILE_SPAN:
            j = i + args.min_len
            lo, hi = min(seg), max(seg)
            while j < n:
                lo2, hi2 = min(lo, a[j]), max(hi, a[j])
                if hi2 - lo2 > TILE_SPAN:
                    break
                lo, hi = lo2, hi2
                j += 1
            runs.append((i * 4, j - i, lo, hi))
            i = j
        else:
            i += 1
    print(f"# {os.path.basename(args.file)}: {len(runs)} kolona sa rasponom <= 2^18\n")
    print(f"{'offset':>10} {'duzina':>7}  {'od':>13} {'do':>13}  tumacenje")
    for off, ln, lo, hi in runs[:args.limit]:
        v = lo / 1e7
        if 24 < v < 79:
            t = f"SIRINA  {v:.5f}°"
        elif 60 < v < 130:
            t = f"DUZINA  {(lo - LON_BIAS) / 1e7:.5f}°  (sirovo {v:.4f})"
        elif v < 1:
            t = f"VISINA? {lo} .. {hi}"
        else:
            t = "?"
        print(f"0x{off:08x} {ln:7d}  {lo / 1e7:13.6f} {hi / 1e7:13.6f}  {t}")


def cmd_sniff(args):
    """Trazi kompresovane delove u telima blokova i pokusava da ih raspakuje.

    Iz `COrionContainerBase::uncompress`: tip kompresije je 2 ili 3, a kompresori
    su zlib i LZMA. Ovde se to proverava empirijski — trazi se zlib/LZMA potpis
    i odmah pokusava dekompresija.
    """
    import zlib
    import lzma
    size = os.path.getsize(args.file)
    f = open(args.file, "rb")
    off, n = 0, 0
    zl_ok = zl_try = lz_ok = lz_try = 0
    total_in = total_out = 0
    samples = []
    while n < args.limit:
        f.seek(off)
        hdr = f.read(0x20)
        if len(hdr) < 0x20:
            break
        nm, _ = read_lp(hdr, 0)
        (bsize,) = struct.unpack_from("<I", hdr, 0x10)
        if nm is None or bsize == 0 or off + bsize > size:
            break
        f.seek(off)
        blk = f.read(bsize)
        for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", blk[0x20:]):
            pos = 0x20 + m.start()
            zl_try += 1
            try:
                dobj = zlib.decompressobj()
                out = dobj.decompress(blk[pos:])
                if len(out) > 64:
                    zl_ok += 1
                    used = len(blk) - pos - len(dobj.unused_data)
                    total_in += used
                    total_out += len(out)
                    if len(samples) < 3:
                        samples.append((off, pos, used, len(out), out[:48]))
            except zlib.error:
                pass
        for m in re.finditer(rb"\x5d\x00\x00", blk[0x20:]):
            pos = 0x20 + m.start()
            lz_try += 1
            try:
                out = lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(blk[pos:])
                if len(out) > 64:
                    lz_ok += 1
            except lzma.LZMAError:
                pass
        off += bsize
        n += 1
    f.close()
    print(f"# {os.path.basename(args.file)}: prosetano {n} blokova")
    print(f"  zlib potpisa: {zl_try}, uspesno raspakovano: {zl_ok}")
    print(f"  LZMA potpisa: {lz_try}, uspesno raspakovano: {lz_ok}")
    if total_in:
        print(f"  ukupno {total_in} -> {total_out} B  (odnos {total_out / total_in:.2f}x)")
    for o, pos, used, olen, head in samples:
        print(f"\n  blok 0x{o:08x} +0x{pos:x}: {used} -> {olen} B")
        print(f"    prvih 48: {head.hex(' ')}")
        print(f"    ascii   : " + "".join(chr(b) if 32 <= b < 127 else "." for b in head))


def cmd_decode(args):
    """Dekodiraj red vrednosti jednog bloka koristeci njegovu semu."""
    size = os.path.getsize(args.file)
    win = min(args.window, size)
    with open(args.file, "rb") as f:
        f.seek(size - win)
        data = f.read(win)
    blocks = find_blocks(data, base=size - win)
    if not -len(blocks) <= args.index < len(blocks):
        raise SystemExit(f"indeks van opsega (0..{len(blocks) - 1})")
    s, e = blocks[args.index]
    blk = data[s - (size - win):e - (size - win)]
    cols, types = parse_records(blk)

    idx = args.index if args.index >= 0 else len(blocks) + args.index
    names, mode = align_cols(cols, types)
    inherited = None
    if names is None:
        cols2, inherited = resolve_cols(cols, types, blocks, data, size - win, idx)
        names, mode = align_cols(cols2, types)
    if names is None:
        names = [nm for nm, _ in cols]
        mode = "neporavnato"

    last = None
    for m in re.finditer(rb"\x02(.)(....)\x01", blk, re.S):
        last = m.end()
    if last is None:
        raise SystemExit("blok nema 02 zapise (nema seme)")

    # posle sema-zapisa ide niz zastavica (po jedna na kolonu), pa spakovan red
    row_start = last + len(types) + args.skip
    width = sum(w for _, w in types)
    row = blk[row_start:row_start + width]

    print(f"# blok {args.index}: 0x{s:08x}-0x{e:08x}  ime={block_name(blk)}")
    print(f"# sema: {len(cols)} imena, {len(types)} tipova, red = {width} B "
          f"na +0x{row_start:x} (apsolutno 0x{s + row_start:08x})")
    print(f"# poravnanje imena: {mode}")
    if inherited is not None:
        print(f"# imena nasledjena iz bloka {inherited}")
    if len(row) < width:
        print(f"UPOZORENJE: dostupno samo {len(row)} B, probaj drugi --skip")
    print(f"# sirovo: {row.hex(' ')}\n")

    off = 0
    for i, (tcode, w) in enumerate(types):
        name = names[i] if i < len(names) else f"<kolona {i}>"
        disp, _ = decode_value(tcode, row[off:off + w])
        print(f"  {name:22s} tip='{chr(tcode)}' {w}B  = {disp}")
        off += w

    named = {names[i]: types[i] for i in range(min(len(names), len(types)))}
    if {"LongitudeBegin", "LatitudeEnd"} <= set(named):
        vals, off = {}, 0
        for i, (tcode, w) in enumerate(types):
            if i < len(names):
                vals[names[i]] = decode_value(tcode, row[off:off + w])[1]
            off += w
        try:
            lon0 = vals["LongitudeBegin"] / COORD_SCALE
            lon1 = vals["LongitudeEnd"] / COORD_SCALE
            lat0 = vals["LatitudeBegin"] / COORD_SCALE
            lat1 = vals["LatitudeEnd"] / COORD_SCALE
            print(f"\n# bbox: lon {lon0:.7f} .. {lon1:.7f}   lat {lat0:.7f} .. {lat1:.7f}")
            print(f"  sirina {lon1 - lon0:.7f}°  visina {lat1 - lat0:.7f}°  "
                  f"kvadrat={abs((lon1 - lon0) - (lat1 - lat0)) < 1e-9}")
            sc = vals.get("WGSScaling")
            wpx = vals.get("TerrainWidth")
            if sc and wpx:
                arcsec = (lon1 - lon0) * 3600
                print(f"  {arcsec:.1f} arcsec / {sc} arcsec po uzorku = {arcsec / sc:.1f} uzoraka "
                      f"(TerrainWidth={wpx}, intervala={arcsec / sc - 1:.0f})")
                print(f"  rezolucija ~ {sc * 30.87:.0f} m")
        except (KeyError, TypeError):
            pass


def cmd_block(args):
    size = os.path.getsize(args.file)
    win = min(args.window, size)
    with open(args.file, "rb") as f:
        f.seek(size - win)
        data = f.read(win)
    blocks = find_blocks(data, base=size - win)
    if not -len(blocks) <= args.index < len(blocks):
        raise SystemExit(f"indeks van opsega (0..{len(blocks) - 1})")
    s, e = blocks[args.index]
    blk = data[s - (size - win):e - (size - win)]
    print(f"# blok {args.index}: 0x{s:08x}-0x{e:08x}  ({e - s} B)")
    print(f"# ime: {block_name(blk)}\n")
    cols, types = parse_records(blk)
    print("kolone (01 zapisi):")
    for nm, t in cols:
        print(f"  {nm:26s} tip=0x{t:02x} '{chr(t)}'  {TYPE_NAMES.get(t, '?')}")
    print("\ntipovi i sirine (02 zapisi):")
    total = 0
    for t, w in types:
        total += w
        print(f"  tip=0x{t:02x} '{chr(t)}'  sirina={w}")
    print(f"\n  suma sirina = {total} B  -> ocekivana sirina jednog reda")


def main():
    p = argparse.ArgumentParser(description="Parser blok-strukture .ATLAS")
    sub = p.add_subparsers(dest="cmd", required=True)
    st = sub.add_parser("stats", help="globalni opseg detektovanih kolona")
    st.add_argument("file")
    st.add_argument("--min-len", type=int, default=200)
    st.set_defaults(func=cmd_stats)

    tl = sub.add_parser("tiles", help="nadji kolone koordinata (int32 x 1e7)")
    tl.add_argument("file")
    tl.add_argument("--min-len", type=int, default=200)
    tl.add_argument("--limit", type=int, default=20)
    tl.set_defaults(func=cmd_tiles)

    g = sub.add_parser("geo", help="nadji nizove koordinata u raspakovanom sadrzaju")
    g.add_argument("file")
    g.add_argument("--lon-min", type=float, default=-12.0)
    g.add_argument("--lon-max", type=float, default=42.7)
    g.add_argument("--lat-min", type=float, default=24.3)
    g.add_argument("--lat-max", type=float, default=79.0)
    g.add_argument("--align", type=int, default=1)
    g.add_argument("--min-run", type=int, default=4)
    g.add_argument("--min-step", type=int, default=1,
                   help="odbaci preklapajuce pogotke; realna sirina zapisa je >= 8")
    g.add_argument("--limit", type=int, default=4)
    g.add_argument("--show", type=int, default=6)
    g.set_defaults(func=cmd_geo)

    rc = sub.add_parser("records", help="parsiraj tagovan zapis iz raspakovanog sadrzaja")
    rc.add_argument("file")
    rc.add_argument("--limit", type=int, default=25)
    rc.set_defaults(func=cmd_records)

    up = sub.add_parser("unpack", help="raspakuj kompresovane blokove")
    up.add_argument("file")
    up.add_argument("--limit", type=int, default=10 ** 7)
    up.add_argument("--out", help="upisi raspakovan sadrzaj u fajl")
    up.set_defaults(func=cmd_unpack)

    sn = sub.add_parser("sniff", help="nadji i raspakuj kompresovane delove")
    sn.add_argument("file")
    sn.add_argument("--limit", type=int, default=400)
    sn.set_defaults(func=cmd_sniff)

    w = sub.add_parser("walk", help="prodji lanac blokova preko polja Size")
    w.add_argument("file")
    w.add_argument("--start", type=lambda x: int(x, 0), default=0)
    w.add_argument("--limit", type=int, default=10 ** 7)
    w.add_argument("--verbose", action="store_true")
    w.set_defaults(func=cmd_walk)

    h = sub.add_parser("header", help="Orion heder + provere iz koda")
    h.add_argument("file")
    h.set_defaults(func=cmd_header)

    for name, fn in (("scan", cmd_scan), ("block", cmd_block), ("decode", cmd_decode)):
        sp = sub.add_parser(name)
        sp.add_argument("file")
        sp.add_argument("--window", type=lambda x: int(x, 0), default=1 << 20)
        if name == "scan":
            sp.add_argument("--limit", type=int, default=20)
        else:
            sp.add_argument("--index", type=int, required=True)
        if name == "decode":
            sp.add_argument("--skip", type=int, default=0,
                            help="fina korekcija pocetka reda ako sema ne legne")
        sp.set_defaults(func=fn)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
