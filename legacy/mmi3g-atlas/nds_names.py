#!/usr/bin/env python3
"""
nds_names.py — vadi imena (ulice, mesta) iz NDS `.psf` fajla.

Nalaz na `SerbiaMontenegroKosovo_Basic.psf` (MIB1, izdanje 2026-04-01):
sadržaj NIJE šifrovan. Imena stoje u tabeli sa prostim zapisom:

    a1 <UTF-8 ime> 00        stvarno ime
    a1 <maska> 00            fonetska maska za glasovni unos: slova
                             zamenjena znakom '?', razmaci zadržani

Maska je korisna kao potvrda: ako se dužina maske poklapa sa dužinom
imena, zapis je pročitan ispravno.

Komande:
  list  <psf> [--limit N] [--min-len N]   izlistaj imena
  stats <psf>                             statistika i uzorak
  grep  <psf> <tekst>                     nađi imena koja sadrže tekst
"""

import argparse
import os
import re
import sys

TAG = 0xA1


def iter_names(path, min_len=3):
    """Prolazi kroz fajl i vraća (offset, ime, ima_masku)."""
    data = open(path, "rb").read()
    n = len(data)
    i = 0
    while True:
        i = data.find(bytes([TAG]), i)
        if i < 0 or i + 1 >= n:
            break
        end = data.find(b"\x00", i + 1)
        if end < 0:
            break
        raw = data[i + 1:end]
        i = end + 1
        if not (min_len <= len(raw) <= 120):
            continue
        try:
            s = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # odbaci binarno smeće: mora imati slovo i biti pretežno štampivo
        if not any(c.isalpha() for c in s):
            continue
        if sum(1 for c in s if c.isprintable()) < len(s):
            continue
        # maska je isti zapis odmah iza, sa '?' umesto slova
        maska = False
        if i < n and data[i] == TAG:
            e2 = data.find(b"\x00", i + 1)
            if 0 < e2 < i + 130:
                m = data[i + 1:e2]
                if m.count(b"?") and len(m) == len(raw):
                    maska = True
        if s.count("?") > len(s) // 2:      # sama maska, ne ime
            continue
        yield i, s, maska


def cmd_list(args):
    n = 0
    for off, s, m in iter_names(args.file, args.min_len):
        print(f"0x{off:08x}  {'M' if m else ' '}  {s}")
        n += 1
        if n >= args.limit:
            break


def cmd_stats(args):
    imena = {}
    sa_maskom = 0
    for off, s, m in iter_names(args.file, args.min_len):
        imena[s] = imena.get(s, 0) + 1
        if m:
            sa_maskom += 1
    uk = sum(imena.values())
    print(f"# {os.path.basename(args.file)}  ({os.path.getsize(args.file):,} B)")
    print(f"  zapisa imena:      {uk:,}")
    print(f"  različitih imena:  {len(imena):,}")
    print(f"  sa fonetskom maskom: {sa_maskom:,}  ({sa_maskom / max(1, uk) * 100:.1f}%)")
    print("\n# najčešća imena")
    for s, c in sorted(imena.items(), key=lambda x: -x[1])[:12]:
        print(f"   {c:5d}  {s}")
    dia = [s for s in imena if re.search(r"[čćžšđČĆŽŠĐ]", s)]
    print(f"\n# imena sa dijakriticima: {len(dia):,}")
    for s in dia[:8]:
        print(f"   {s}")


def cmd_grep(args):
    n = 0
    for off, s, m in iter_names(args.file, args.min_len):
        if args.tekst.lower() in s.lower():
            print(f"0x{off:08x}  {s}")
            n += 1
            if n >= args.limit:
                break
    if n == 0:
        print("nema pogodaka")


def main():
    p = argparse.ArgumentParser(description="Imena iz NDS .psf fajla")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("list", cmd_list), ("stats", cmd_stats), ("grep", cmd_grep)):
        sp = sub.add_parser(name)
        sp.add_argument("file")
        if name == "grep":
            sp.add_argument("tekst")
        sp.add_argument("--limit", type=int, default=40)
        sp.add_argument("--min-len", type=int, default=3)
        sp.set_defaults(func=fn)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
