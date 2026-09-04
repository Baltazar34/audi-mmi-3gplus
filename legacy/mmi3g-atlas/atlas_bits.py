#!/usr/bin/env python3
"""
atlas_bits.py — bitovni čitač za Orion kolone tipa 3.

Rekonstruisan iz `FUN_08331740` (rukovalac za kod kompresije 3) u NavCore.
Stanje čitača u binarnom fajlu:
  param_2[0]            pokazivač na sledeću u32 reč
  param_2[1]            bafer preostalih bitova
  *(u16*)(param_2 + 8)  koliko bitova je ostalo u baferu

Čitanje n bitova:
  ako je ostalo < n:  učitaj sledeću u32, vrednost = bafer | (nova << ostalo),
                      bafer = nova >> (n - ostalo), ostalo += 32 - n
  inače:              vrednost = bafer, bafer >>= n, ostalo -= n
  rezultat = vrednost & ((1 << n) - 1)

Dakle **LSB-first unutar little-endian u32 reči**.

Zaglavlje kolone je 5 bitova: `sign_extend_5(v) + 1` = širina svake naredne vrednosti.

Komande:
  probe <fajl> --count N   skeniraj offsete i nadji koherentne nizove
  read  <fajl> --offset O --count N [--signed]
"""

import argparse
import os
import struct


class BitReader:
    """Verno prati logiku iz FUN_08331740."""

    def __init__(self, data, byte_off=0):
        self.d = data
        self.pos = byte_off
        self.buf = 0
        self.avail = 0

    def read(self, n):
        if n <= 0 or n > 32:
            raise ValueError(f"nedozvoljena širina {n}")
        if self.avail < n:
            if self.pos + 4 > len(self.d):
                raise EOFError
            nxt = int.from_bytes(self.d[self.pos:self.pos + 4], "little")
            self.pos += 4
            val = self.buf | (nxt << self.avail)
            used = n - self.avail
            self.buf = (nxt >> used) if used < 32 else 0
            self.avail = self.avail + 32 - n
        else:
            val = self.buf
            self.buf >>= n
            self.avail -= n
        return val & ((1 << n) - 1)


def sign_extend(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m


def read_column(data, byte_off, count, signed=True, width_mode="unsigned"):
    """Pročitaj 5-bitnu širinu pa `count` vrednosti te širine.

    Kod u `FUN_08331740` polje ZNAKOVNO proširuje: `sign_extend_5(v) + 1`.
    Time se dobija opseg -15..16, pa širine preko 16 nisu predstavljive —
    negativna vrednost skoro sigurno označava poseban slučaj (konstantna
    kolona ili neupakovan zapis), a ne širinu. Zato su podržana oba čitanja:
      "unsigned" (podrazumevano) : width = v + 1, opseg 1..32
      "signed"                   : verno kodu, width = sign_extend_5(v) + 1
    """
    br = BitReader(data, byte_off)
    raw = br.read(5)
    width = (raw + 1) if width_mode == "unsigned" else (sign_extend(raw, 5) + 1)
    if not (1 <= width <= 32):
        return None, width, []
    vals = []
    for _ in range(count):
        v = br.read(width)
        vals.append(sign_extend(v, width) if signed else v)
    return br, width, vals


def cmd_read(args):
    data = open(args.file, "rb").read()
    br, width, vals = read_column(data, args.offset, args.count, args.signed,
                                  args.width_mode)
    print(f"# offset 0x{args.offset:x}, širina iz zaglavlja = {width} bita")
    if br is None:
        print("  širina van opsega 1..32 — ovo nije početak kolone tipa 3")
        return
    print(f"  pročitano {len(vals)} vrednosti, potrošeno do bajta 0x{br.pos:x}")
    print(f"  min={min(vals)} max={max(vals)}")
    print("  prvih 12:", ", ".join(str(v) for v in vals[:12]))
    acc, cum = 0, []
    for v in vals:
        acc += v
        cum.append(acc)
    print(f"  kumulativno: min={min(cum)} max={max(cum)}  (ako je delta kodovano)")
    print("  prvih 8 kumulativno:", ", ".join(str(v) for v in cum[:8]))


def cmd_probe(args):
    """Prođi bajt po bajt i traži offset gde kolona ima smisla.

    Kriterijum: širina u razumnom opsegu i vrednosti koje se, kad se
    kumulativno saberu, drže u opsegu jednog tajla.
    """
    data = open(args.file, "rb").read()
    hits = []
    for off in range(args.start, min(len(data) - 8, args.end), args.step):
        try:
            br, width, vals = read_column(data, off, args.count, True, args.width_mode)
        except EOFError:
            break
        if br is None or not (args.min_width <= width <= args.max_width):
            continue
        if not vals:
            continue
        acc, cum = 0, []
        for v in vals:
            acc += v
            cum.append(acc)
        span = max(cum) - min(cum)
        if 0 < span <= args.max_span:
            hits.append((off, width, span, min(cum), max(cum)))
    hits.sort(key=lambda h: h[2])
    print(f"# {os.path.basename(args.file)}: {len(hits)} kandidata "
          f"(širina {args.min_width}..{args.max_width}, raspon <= {args.max_span})\n")
    for off, width, span, lo, hi in hits[:args.limit]:
        print(f"  0x{off:06x}  širina={width:2d}  raspon kumulativa={span:>12d}  "
              f"[{lo} .. {hi}]")
        if args.degrees:
            print(f"            u stepenima: {lo / 1e7:.7f} .. {hi / 1e7:.7f}")


def main():
    p = argparse.ArgumentParser(description="Bitovni čitač Orion kolona (tip 3)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("read", help="pročitaj jednu kolonu")
    r.add_argument("file")
    r.add_argument("--offset", type=lambda x: int(x, 0), required=True)
    r.add_argument("--count", type=int, default=302)
    r.add_argument("--signed", action="store_true", default=True)
    r.add_argument("--width-mode", choices=("unsigned", "signed"), default="unsigned")
    r.set_defaults(func=cmd_read)

    pr = sub.add_parser("probe", help="skeniraj offsete")
    pr.add_argument("file")
    pr.add_argument("--count", type=int, default=302)
    pr.add_argument("--start", type=lambda x: int(x, 0), default=0)
    pr.add_argument("--end", type=lambda x: int(x, 0), default=1 << 30)
    pr.add_argument("--step", type=int, default=1)
    pr.add_argument("--min-width", type=int, default=4)
    pr.add_argument("--max-width", type=int, default=32)
    pr.add_argument("--max-span", type=int, default=20_000_000)
    pr.add_argument("--limit", type=int, default=15)
    pr.add_argument("--degrees", action="store_true")
    pr.add_argument("--width-mode", choices=("unsigned", "signed"), default="unsigned")
    pr.set_defaults(func=cmd_probe)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
