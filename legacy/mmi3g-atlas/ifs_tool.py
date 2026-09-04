#!/usr/bin/env python3
"""
ifs_tool.py — raspakivanje QNX IFS image-a iz MMI 3G+ firmware paketa (MU9411).

Bez ijedne spoljne zavisnosti: čist Python 3 stdlib, uključujući sopstveni
LZO1X dekompresor. Ništa se ne skida sa interneta.

Format koji obrađuje:
  [startup_header 256B][startup kod][2B BE dužina][LZO1X blok] ... [0x0000]

Komande:
  info   <ifs>              ispiši startup header
  unpack <ifs> <out.raw>    dekompresuj imagefs u sirovi fajl
  ls     <raw>              izlistaj fajlove iz imagefs direktorijuma
  extract <raw> <outdir>    izvuci sve fajlove
"""

import argparse
import os
import struct
import sys

SIGNATURE = 0x00FF7EEB
COMPRESS = {0x00: "NONE", 0x04: "ZLIB", 0x08: "LZO", 0x0C: "UCL"}


# ---------------------------------------------------------------- LZO1X

def lzo1x_decompress(src):
    """Port referentnog lzo1x_decompress. Vraća bytes."""
    out = bytearray()
    ip = 0
    m_pos = 0
    t = 0

    def emit(pos, count):
        # preklapanje je legitimno u LZO (RLE efekat) -> tada bajt po bajt
        if pos + count <= len(out):
            out.extend(out[pos:pos + count])
        else:
            for i in range(count):
                out.append(out[pos + i])

    if src[ip] > 17:
        t = src[ip] - 17
        ip += 1
        if t < 4:
            label = "match_next"
        else:
            out.extend(src[ip:ip + t])
            ip += t
            label = "first_literal_run"
    else:
        label = "top"

    while True:
        if label == "top":
            t = src[ip]
            ip += 1
            if t >= 16:
                label = "match"
                continue
            if t == 0:
                while src[ip] == 0:
                    t += 255
                    ip += 1
                t += 15 + src[ip]
                ip += 1
            n = t + 3
            out.extend(src[ip:ip + n])
            ip += n
            label = "first_literal_run"
            continue

        if label == "first_literal_run":
            t = src[ip]
            ip += 1
            if t >= 16:
                label = "match"
                continue
            m_pos = len(out) - (1 + 0x0800) - (t >> 2) - (src[ip] << 2)
            ip += 1
            emit(m_pos, 3)
            label = "match_done"
            continue

        if label == "match":
            if t >= 64:
                m_pos = len(out) - 1 - ((t >> 2) & 7) - (src[ip] << 3)
                ip += 1
                t = (t >> 5) - 1
                label = "copy_match"
                continue
            elif t >= 32:
                t &= 31
                if t == 0:
                    while src[ip] == 0:
                        t += 255
                        ip += 1
                    t += 31 + src[ip]
                    ip += 1
                m_pos = len(out) - 1 - (int.from_bytes(src[ip:ip + 2], "little") >> 2)
                ip += 2
                label = "copy_match"
                continue
            elif t >= 16:
                m_pos = len(out) - ((t & 8) << 11)
                t &= 7
                if t == 0:
                    while src[ip] == 0:
                        t += 255
                        ip += 1
                    t += 7 + src[ip]
                    ip += 1
                m_pos -= int.from_bytes(src[ip:ip + 2], "little") >> 2
                ip += 2
                if m_pos == len(out):
                    break  # eof marker
                m_pos -= 0x4000
                label = "copy_match"
                continue
            else:
                m_pos = len(out) - 1 - (t >> 2) - (src[ip] << 2)
                ip += 1
                emit(m_pos, 2)
                label = "match_done"
                continue

        if label == "copy_match":
            emit(m_pos, t + 2)
            label = "match_done"
            continue

        if label == "match_done":
            t = src[ip - 2] & 3
            if t == 0:
                label = "top"
                continue
            label = "match_next"
            continue

        if label == "match_next":
            out.extend(src[ip:ip + t])
            ip += t
            t = src[ip]
            ip += 1
            label = "match"
            continue

    return bytes(out)


# ---------------------------------------------------------------- header

def parse_header(path):
    d = open(path, "rb").read(256)
    sig, ver, f1, f2, hs, mach = struct.unpack_from("<IHBBHH", d, 0)
    if sig != SIGNATURE:
        sys.exit(f"{path}: nije QNX IFS (signature 0x{sig:08x})")
    (startup_vaddr, paddr_bias, image_paddr, ram_paddr, ram_size,
     startup_size, stored_size, imagefs_paddr, imagefs_size) = struct.unpack_from("<9I", d, 12)
    return dict(version=ver, flags1=f1, flags2=f2, header_size=hs, machine=mach,
                compress=COMPRESS.get(f1 & 0x1C, "?"),
                bigendian=bool(f1 & 2), startup_vaddr=startup_vaddr,
                paddr_bias=paddr_bias, image_paddr=image_paddr, ram_paddr=ram_paddr,
                ram_size=ram_size, startup_size=startup_size, stored_size=stored_size,
                imagefs_paddr=imagefs_paddr, imagefs_size=imagefs_size)


def cmd_info(args):
    h = parse_header(args.ifs)
    print(f"# {args.ifs}  ({os.path.getsize(args.ifs)} bajtova)")
    for k, v in h.items():
        if isinstance(v, int) and v > 255:
            print(f"  {k:14s} 0x{v:08x}  ({v})")
        else:
            print(f"  {k:14s} {v}")
    if h["machine"] == 42:
        print("\n  machine 42 = EM_SH -> u Ghidri jezik SuperH4:LE:32:default")


# ---------------------------------------------------------------- unpack

def cmd_unpack(args):
    h = parse_header(args.ifs)
    if h["compress"] != "LZO":
        sys.exit(f"kompresija {h['compress']} nije podržana ovim alatom")

    data = open(args.ifs, "rb").read()
    off = h["startup_size"]
    total = 0
    nblocks = 0
    with open(args.out, "wb") as fo:
        while off + 2 <= len(data):
            (clen,) = struct.unpack_from(">H", data, off)
            off += 2
            if clen == 0:
                break
            block = data[off:off + clen]
            off += clen
            plain = lzo1x_decompress(block)
            fo.write(plain)
            total += len(plain)
            nblocks += 1
            if nblocks % 100 == 0:
                pct = total / h["imagefs_size"] * 100
                print(f"\r  blokova {nblocks}, {total / 1048576:.1f} MB ({pct:.1f}%)",
                      end="", flush=True)
    print(f"\r  blokova {nblocks}, {total / 1048576:.1f} MB" + " " * 20)
    print(f"raspakovano u {args.out}")
    if total != h["imagefs_size"]:
        print(f"UPOZORENJE: dobijeno {total}, header kaže {h['imagefs_size']} "
              f"(razlika {total - h['imagefs_size']})")
    else:
        print("veličina se poklapa sa imagefs_size iz hedera")


# ---------------------------------------------------------------- imagefs

def parse_dir(raw):
    """Prolazi kroz imagefs direktorijum i vraća listu unosa."""
    if raw[:7] != b"imagefs":
        sys.exit("nije imagefs image (nema magic na offsetu 0)")
    # struct image_header
    (image_size, hdr_dir_size, dir_offset) = struct.unpack_from("<3I", raw, 8)
    entries = []
    off = dir_offset
    end = hdr_dir_size
    while off < end:
        size, extattr_offset, ino, mode, gid, uid, mtime = struct.unpack_from("<HHIIIII", raw, off)
        if size == 0:
            break
        rec = raw[off:off + size]
        ftype = (mode >> 12) & 0xF
        if ftype == 0x8:      # regular file
            foff, fsize = struct.unpack_from("<II", rec, 24)
            name = rec[32:].split(b"\x00")[0].decode("latin-1")
            entries.append(dict(kind="file", name=name, offset=foff, size=fsize,
                                mode=mode, ino=ino))
        elif ftype == 0xA:    # symlink
            sym_off, sym_size = struct.unpack_from("<HH", rec, 24)
            rest = rec[28:]
            name = rest.split(b"\x00")[0].decode("latin-1")
            target = rest[len(name) + 1:].split(b"\x00")[0].decode("latin-1")
            entries.append(dict(kind="link", name=name, target=target, mode=mode, ino=ino))
        elif ftype == 0x4:    # directory
            name = rec[24:].split(b"\x00")[0].decode("latin-1")
            entries.append(dict(kind="dir", name=name, mode=mode, ino=ino))
        off += size
    return entries


def cmd_ls(args):
    raw = open(args.raw, "rb").read()
    entries = parse_dir(raw)
    for e in entries:
        if e["kind"] == "file":
            print(f"{e['size']:10d}  {e['name']}")
        elif e["kind"] == "link":
            print(f"{'':10s}  {e['name']} -> {e['target']}")
        else:
            print(f"{'<dir>':>10s}  {e['name']}")
    print(f"\nukupno unosa: {len(entries)}")


def cmd_extract(args):
    raw = open(args.raw, "rb").read()
    entries = parse_dir(raw)
    n = 0
    for e in entries:
        if e["kind"] != "file":
            continue
        dest = os.path.join(args.outdir, e["name"].lstrip("/"))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "wb") as f:
            f.write(raw[e["offset"]:e["offset"] + e["size"]])
        n += 1
    print(f"izvučeno {n} fajlova u {args.outdir}")


# ---------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description="QNX IFS alat za MMI 3G+ firmware")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("info", help="startup header")
    i.add_argument("ifs")
    i.set_defaults(func=cmd_info)

    u = sub.add_parser("unpack", help="dekompresuj imagefs")
    u.add_argument("ifs")
    u.add_argument("out")
    u.set_defaults(func=cmd_unpack)

    l = sub.add_parser("ls", help="izlistaj sadržaj raspakovanog imagefs-a")
    l.add_argument("raw")
    l.set_defaults(func=cmd_ls)

    e = sub.add_parser("extract", help="izvuci fajlove")
    e.add_argument("raw")
    e.add_argument("outdir")
    e.set_defaults(func=cmd_extract)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
