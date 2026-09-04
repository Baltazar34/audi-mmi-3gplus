#!/usr/bin/env python3
"""fw_protection_model.py — read-only mapiranje modela zastite u NavCore.

Cilj je iskljucivo faktografija: koje provere postoje, kojim redom, i koji
konfig kljucevi ih iskljucuju.  Skripta NE pravi bypass, ne menja binar i
ne generise nikakav patch.  Cita `MMI3GNavigation`/`NavCore` kao podatke.

Radi na nivou stringova i njihovih referenci u SH4 literal pool-u:
  * nadje svaki string zastite i njegovu virtuelnu adresu (VA);
  * skenira ceo binar za u32 (LE) jednak toj VA — to su pool slotovi;
  * dumpuje okolinu i pokusava da prepozna tabelu (niz susednih pointera).

VA se racuna iz ELF program headera (fizicki offset segmenta + p_vaddr).
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


def elf_segments(data: bytes):
    """Vrati [(file_off, vaddr, filesz)] za PT_LOAD segmente (ELF32 LE)."""
    assert data[:4] == b"\x7fELF" and data[4] == 1, "nije ELF32"
    e_phoff = struct.unpack_from("<I", data, 0x1C)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x2A)[0]
    e_phnum = struct.unpack_from("<H", data, 0x2C)[0]
    segments = []
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        p_type, p_off, p_vaddr, _p_paddr, p_filesz = struct.unpack_from("<IIIII", data, base)
        if p_type == 1:  # PT_LOAD
            segments.append((p_off, p_vaddr, p_filesz))
    return segments


def off_to_va(segments, off):
    for f_off, vaddr, filesz in segments:
        if f_off <= off < f_off + filesz:
            return vaddr + (off - f_off)
    return None


def va_to_off(segments, va):
    for f_off, vaddr, filesz in segments:
        if vaddr <= va < vaddr + filesz:
            return f_off + (va - vaddr)
    return None


def find_all(data: bytes, needle: bytes):
    out, i = [], data.find(needle)
    while i >= 0:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", type=Path)
    ap.add_argument("--context", type=int, default=48)
    args = ap.parse_args()
    data = args.binary.read_bytes()
    seg = elf_segments(data)
    print(f"# {args.binary.name}  {len(data):,} B  PT_LOAD segmenata: {len(seg)}")
    for f_off, vaddr, filesz in seg:
        print(f"  seg file 0x{f_off:x}  va 0x{vaddr:x}  size 0x{filesz:x}")

    keys = [
        b"skipCheckSignatureAndVariant", b"skipCheckRegion",
        b"skipCheckConsistencyImages", b"skipCheckCrc", b"skipCheck",
        b"eCheckSignature", b"eCheckCrc", b"eWaitForActivation",
        b"checkSignature", b"CheckSignature", b"eAnalyseCheckedPackages",
        b"FSC", b"Fsc", b"fsc", b"PartNumber", b"variant", b"Variant",
    ]
    print("\n# stringovi i pool reference")
    for key in keys:
        hits = find_all(data, key + b"\x00")
        if not hits:
            hits = find_all(data, key)
            if not hits:
                print(f"  [MISS] {key.decode()}")
                continue
        off = hits[0]
        va = off_to_va(seg, off)
        line = f"  {key.decode():<28} off=0x{off:x}"
        if va is not None:
            line += f" va=0x{va:x}"
            pool = find_all(data, struct.pack("<I", va))
            line += f"  pool_refs={len(pool)}"
            print(line)
            for p in pool[:6]:
                pva = off_to_va(seg, p)
                print(f"      slot off=0x{p:x} va={'0x%x'%pva if pva else '?'}  "
                      f"okolina: {data[p-8:p+8].hex(' ')}")
        else:
            line += "  (van segmenata)"
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
