#!/usr/bin/env python3
"""
atlas_recon.py — prva faza reverse engineeringa binarnog formata.
Bez zavisnosti: samo Python 3.8+ stdlib. Radi nativno na Apple Silicon.

Namenjeno .ATLAS fajlovima iz MMI 3G+ pkgdb paketa, ali je format-agnostično.

Komande:
  head    heksdump početka + detekcija magic bajtova
  ent     entropija po blokovima -> kompresovano/enkriptovano vs strukturirano
  str     stringovi sa offsetima (ASCII + UTF-16LE)
  coord   known-answer: traži poznatu koordinatu u raznim fixed-point kodovima
  period  traži veličinu ponavljajućeg zapisa (record size)
  diff    poredi dva izdanja istog paketa po blokovima

Primeri:
  python3 atlas_recon.py head  PSD.ATLAS
  python3 atlas_recon.py ent   PSD.ATLAS --block 65536
  python3 atlas_recon.py str   PSD.ATLAS --min 6 --limit 200
  python3 atlas_recon.py coord PSD.ATLAS --lat 44.7866 --lon 20.4489
  python3 atlas_recon.py period PSD.ATLAS --offset 0x1000 --len 262144
  python3 atlas_recon.py diff  6.35.1/PSD.ATLAS 6.36.1/PSD.ATLAS
"""

import argparse
import math
import os
import struct
import sys
from collections import Counter

CHUNK = 1 << 20
SECTOR = 2048          # CDM_CD_SECTOR_SIZE(), potvrdjeno iz NavCore koda

# ---------------------------------------------------------------- utilities

def read_at(path, offset, length):
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(length)


def shannon(data):
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def hexdump(data, base=0, width=16):
    out = []
    for i in range(0, len(data), width):
        row = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in row).ljust(width * 3 - 1)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(f"{base + i:08x}  {hexpart}  |{asciipart}|")
    return "\n".join(out)


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f}{unit}" if unit != "B" else f"{n}B"
        n /= 1024


# ---------------------------------------------------------------- head

def cmd_head(args):
    size = os.path.getsize(args.file)
    data = read_at(args.file, 0, args.bytes)
    print(f"# {args.file}  ({human(size)}, {size} bajtova)\n")
    print(hexdump(data))

    print("\n# repovi i poravnanja")
    tail = read_at(args.file, max(0, size - 256), 256)
    print(hexdump(tail, base=max(0, size - 256)))

    print("\n# napomene")
    magic = data[:8]
    printable = sum(1 for b in magic if 32 <= b < 127)
    if printable >= 4:
        print(f"  magic izgleda tekstualno: {magic!r}")
    else:
        print(f"  magic je binarni: {magic.hex(' ')}")

    # tipične veličine iz hedera: proveri da li neki uint32 liči na file size
    for endian, tag in (("<", "LE"), (">", "BE")):
        for off in range(0, min(64, len(data) - 4), 4):
            (val,) = struct.unpack_from(endian + "I", data, off)
            if abs(val - size) <= 4096 and val > 0:
                print(f"  offset 0x{off:02x} ({tag}) = {val} ~ veličina fajla -> kandidat za size polje")
            elif 0 < val < size and val > size * 0.5:
                print(f"  offset 0x{off:02x} ({tag}) = {val} -> mogući offset ka tabeli pri kraju")

    # sektorska interpretacija: NavCore radi sa 2048 B sektorima (potvrdjeno iz koda,
    # cdm_nav_db_driver_nobss.cpp: maska 0x7ff, offset >> 11), i broj sektora stoji
    # u polju sirokom 24 bita. Zato offseti u hederu cesto NISU bajtovi nego sektori.
    print(f"\n# sektorska interpretacija (sektor = {SECTOR} B)")
    nsect = math.ceil(size / SECTOR)
    print(f"  fajl ima {nsect} sektora ({size} B)")
    hits = 0
    for endian, tag in (("<", "LE"), (">", "BE")):
        for off in range(0, min(args.bytes, len(data) - 4), 4):
            (val,) = struct.unpack_from(endian + "I", data, off)
            if val == 0 or val > 0x00FFFFFF:      # 24-bitno polje
                continue
            byte_off = val * SECTOR
            if abs(val - nsect) <= 2:
                print(f"  offset 0x{off:02x} ({tag}) = {val} sektora ~ ukupan broj sektora")
                hits += 1
            elif 0 < byte_off <= size:
                print(f"  offset 0x{off:02x} ({tag}) = {val} sektora -> bajt 0x{byte_off:x} "
                      f"({byte_off / size * 100:.1f}% fajla)")
                hits += 1
    if hits == 0:
        print("  nijedan uint32 se ne uklapa kao broj sektora unutar fajla")
    else:
        print("  (proveri ove offsete sa `head --bytes` na izracunatoj poziciji)")


# ---------------------------------------------------------------- entropy

BARS = "▁▂▃▄▅▆▇█"


def cmd_ent(args):
    size = os.path.getsize(args.file)
    block = args.block
    nblocks = math.ceil(size / block)
    print(f"# entropija: {args.file}  blok={human(block)}  blokova={nblocks}")
    print("# 8.0 = slučajno (kompresovano/enkriptovano), <6.0 = strukturirano\n")

    vals = []
    with open(args.file, "rb") as f:
        for i in range(nblocks):
            buf = f.read(block)
            if not buf:
                break
            vals.append(shannon(buf))

    step = max(1, len(vals) // args.width)
    line = ""
    for i in range(0, len(vals), step):
        window = vals[i:i + step]
        avg = sum(window) / len(window)
        idx = min(7, max(0, int(avg / 8 * 8)))
        line += BARS[idx]
    print(line)

    lo = min(vals)
    hi = max(vals)
    avg = sum(vals) / len(vals)
    print(f"\nmin={lo:.2f}  max={hi:.2f}  prosek={avg:.2f}")

    low_blocks = [(i, v) for i, v in enumerate(vals) if v < 6.0]
    print(f"\nblokova sa entropijom < 6.0: {len(low_blocks)} / {len(vals)}")
    for i, v in low_blocks[:20]:
        print(f"  0x{i * block:08x}  {v:.2f}  <- strukturirano, počni ovde")
    if len(low_blocks) > 20:
        print(f"  ... i još {len(low_blocks) - 20}")

    if avg > 7.9:
        print("\nZAKLJUČAK: ceo fajl je blizu 8.0 — kompresovan ili enkriptovan.")
        print("Ako nema nijednog niskoentropijskog bloka ni na početku, heder je")
        print("takođe zaštićen i statička analiza podataka nema smisla bez parsera.")
    elif lo < 5.0:
        print("\nZAKLJUČAK: postoje jasno strukturirani regioni. To su hederi/indeksi.")
        print("Payload je verovatno kompresovan po tajlovima, a indeksi u čistom.")


# ---------------------------------------------------------------- strings

def cmd_str(args):
    found = 0
    with open(args.file, "rb") as f:
        base = 0
        carry = b""
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            data = carry + buf
            # ASCII
            cur = bytearray()
            start = 0
            for i, b in enumerate(data):
                if 32 <= b < 127:
                    if not cur:
                        start = i
                    cur.append(b)
                else:
                    if len(cur) >= args.min:
                        print(f"{base + start - len(carry):08x}  A  {cur.decode('ascii')}")
                        found += 1
                        if found >= args.limit:
                            return
                    cur = bytearray()
            carry = data[-256:]
            base += len(buf)


# ---------------------------------------------------------------- coord

ENCODINGS = [
    ("deg * 1e5", lambda d: int(round(d * 1e5))),
    ("deg * 1e6", lambda d: int(round(d * 1e6))),
    ("deg * 1e7", lambda d: int(round(d * 1e7))),
    ("milliarcsec", lambda d: int(round(d * 3600000))),
    ("BAMS 2^32/360", lambda d: int(round(d * (2 ** 32) / 360)) & 0xFFFFFFFF),
    ("deg * 2^24/360", lambda d: int(round(d * (2 ** 24) / 360))),
]


def cmd_coord(args):
    """Known-answer attack: znaš gde je tvoja ulica, traži je u fajlu."""
    print(f"# tražim lat={args.lat} lon={args.lon} sa tolerancijom {args.tol}\n")

    targets = []
    for name, fn in ENCODINGS:
        lat_v = fn(args.lat)
        lon_v = fn(args.lon)
        tol = max(1, int(abs(fn(args.tol)) if args.tol else 0))
        targets.append((name, lat_v, lon_v, tol))
        print(f"  {name:16s} lat={lat_v:12d}  lon={lon_v:12d}  +-{tol}")
    print()

    hits = 0
    with open(args.file, "rb") as f:
        base = 0
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            for endian, tag in (("<i", "LE"), (">i", "BE")):
                for off in range(0, len(buf) - 8, 2):
                    try:
                        (a,) = struct.unpack_from(endian, buf, off)
                        (b,) = struct.unpack_from(endian, buf, off + 4)
                    except struct.error:
                        continue
                    for name, lat_v, lon_v, tol in targets:
                        if abs(a - lat_v) <= tol and abs(b - lon_v) <= tol:
                            print(f"{base + off:08x}  {tag}  {name}  lat,lon  ({a}, {b})")
                            hits += 1
                        elif abs(a - lon_v) <= tol and abs(b - lat_v) <= tol:
                            print(f"{base + off:08x}  {tag}  {name}  lon,lat  ({a}, {b})")
                            hits += 1
                    if hits >= args.limit:
                        print("\n(limit dostignut)")
                        return
            base += len(buf)
    print(f"\nukupno pogodaka: {hits}")
    if hits == 0:
        print("Nema pogodaka. Ili je region kompresovan, ili su koordinate delta-kodovane")
        print("u odnosu na origin tajla (najčešći slučaj kod nav formata).")


# ---------------------------------------------------------------- period

def cmd_period(args):
    """Traži veličinu ponavljajućeg zapisa preko autokorelacije."""
    data = read_at(args.file, args.offset, args.len)
    if len(data) < 1024:
        print("premalo podataka")
        return

    print(f"# autokorelacija na 0x{args.offset:x}, {len(data)} bajtova\n")
    scores = []
    for lag in range(2, args.max_lag + 1):
        matches = sum(1 for i in range(len(data) - lag) if data[i] == data[i + lag])
        scores.append((matches / (len(data) - lag), lag))

    scores.sort(reverse=True)
    print("najverovatnije veličine zapisa:")
    seen = set()
    shown = 0
    for score, lag in scores:
        if any(lag % s == 0 for s in seen):
            continue
        print(f"  {lag:5d} bajtova   poklapanje {score * 100:.1f}%")
        seen.add(lag)
        shown += 1
        if shown >= 12:
            break
    print("\nAko je najbolji rezultat blizu 100%, imaš fiksne zapise te veličine.")
    print("Onda hexdumpuj nekoliko uzastopnih i uporedi polje po polje.")


# ---------------------------------------------------------------- diff

def cmd_diff(args):
    a_size = os.path.getsize(args.file_a)
    b_size = os.path.getsize(args.file_b)
    block = args.block
    print(f"# A: {args.file_a}  {human(a_size)}")
    print(f"# B: {args.file_b}  {human(b_size)}")
    print(f"# blok = {human(block)}\n")

    same = 0
    diff = 0
    ranges = []
    cur_start = None

    with open(args.file_a, "rb") as fa, open(args.file_b, "rb") as fb:
        idx = 0
        while True:
            ba = fa.read(block)
            bb = fb.read(block)
            if not ba and not bb:
                break
            if ba == bb:
                same += 1
                if cur_start is not None:
                    ranges.append((cur_start, idx * block))
                    cur_start = None
            else:
                diff += 1
                if cur_start is None:
                    cur_start = idx * block
            idx += 1
    if cur_start is not None:
        ranges.append((cur_start, idx * block))

    total = same + diff
    print(f"identičnih blokova: {same}/{total}  ({same / total * 100:.1f}%)")
    print(f"izmenjenih blokova: {diff}/{total}\n")

    print("regioni koji se razlikuju (verovatno payload):")
    for start, end in ranges[:30]:
        print(f"  0x{start:08x} - 0x{end:08x}   ({human(end - start)})")
    if len(ranges) > 30:
        print(f"  ... i još {len(ranges) - 30}")

    print("\nSve što je BAJT-IDENTIČNO između dva izdanja je struktura, ne podaci:")
    print("hederi, magic, tabele tipova, šeme. Tu počni sa mapiranjem formata.")


# ---------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description="Reverse engineering binarnih nav formata")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("head", help="heksdump početka i kraja")
    h.add_argument("file")
    h.add_argument("--bytes", type=lambda x: int(x, 0), default=512)
    h.set_defaults(func=cmd_head)

    e = sub.add_parser("ent", help="entropija po blokovima")
    e.add_argument("file")
    e.add_argument("--block", type=lambda x: int(x, 0), default=65536)
    e.add_argument("--width", type=int, default=100)
    e.set_defaults(func=cmd_ent)

    s = sub.add_parser("str", help="stringovi sa offsetima")
    s.add_argument("file")
    s.add_argument("--min", type=int, default=6)
    s.add_argument("--limit", type=int, default=500)
    s.set_defaults(func=cmd_str)

    c = sub.add_parser("coord", help="known-answer pretraga koordinata")
    c.add_argument("file")
    c.add_argument("--lat", type=float, required=True)
    c.add_argument("--lon", type=float, required=True)
    c.add_argument("--tol", type=float, default=0.001)
    c.add_argument("--limit", type=int, default=100)
    c.set_defaults(func=cmd_coord)

    pe = sub.add_parser("period", help="veličina ponavljajućeg zapisa")
    pe.add_argument("file")
    pe.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    pe.add_argument("--len", type=lambda x: int(x, 0), default=262144)
    pe.add_argument("--max-lag", type=int, default=512)
    pe.set_defaults(func=cmd_period)

    d = sub.add_parser("diff", help="poredi dva izdanja")
    d.add_argument("file_a")
    d.add_argument("file_b")
    d.add_argument("--block", type=lambda x: int(x, 0), default=4096)
    d.set_defaults(func=cmd_diff)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
