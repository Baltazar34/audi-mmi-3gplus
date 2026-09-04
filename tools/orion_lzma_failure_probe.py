#!/usr/bin/env python3
"""orion_lzma_failure_probe.py — sta je sa blokovima koji se ne raspakuju.

U PSD3 833 CONTAINER bloka (codec 3) baca `LZMAError` sa standardnim
parametrima `lc=3 lp=0 pb=2 dict=64K`.  Ovaj alat za svaki takav blok
proba nezavisne hipoteze i belezi koja daje tacno `usize` bajtova:

  1. druge LZMA1 raw kombinacije lc/lp/pb i dict velicine;
  2. LZMA-alone sa 13-bajtnim zaglavljem;
  3. zlib / raw deflate;
  4. delimicno raspakovanje (koliko bajtova izadje pre greske);
  5. drugi chunk slot, ako postoji.

Nista se ne menja.  Rezultat je raspodela hipoteza koje prolaze.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import struct
import sys
import zlib
from collections import Counter
from pathlib import Path

DEFAULT = (3, 0, 2, 1 << 16)


def raw_lzma(data: bytes, lc: int, lp: int, pb: int, dict_size: int, want: int) -> bytes:
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
        {"id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": dict_size}])
    return d.decompress(data, max_length=want)


def partial(data: bytes, want: int) -> int:
    d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
        {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 16}])
    out = bytearray()
    try:
        for i in range(0, len(data), 256):
            out += d.decompress(data[i:i + 256])
            if len(out) >= want:
                break
    except lzma.LZMAError:
        pass
    return len(out)


def run(path: Path, output: Path, limit: int) -> dict[str, object]:
    size = path.stat().st_size
    off = 0
    outcome = Counter()
    samples = []
    partial_ratio = Counter()
    checked = 0
    with path.open("rb") as f:
        while True:
            f.seek(off); h = f.read(0x20)
            if len(h) < 0x20: break
            nl = h[0]
            if nl == 0 or nl > 15: break
            bs = struct.unpack_from("<I", h, 0x10)[0]
            if bs < 0x20 or off + bs > size: break
            if h[1:1 + nl] == b"CONTAINER" and h[0x20 - 0x20 + 0x1f] is not None:
                f.seek(off); b = f.read(bs)
                if b[0x20] == 3:
                    cnt = b[0x21]
                    pairs = [struct.unpack_from("<II", b, 0x22 + i * 8) for i in range(cnt)]
                    d0 = 0x22 + cnt * 8
                    c0, u0 = pairs[0]
                    payload = b[d0:d0 + c0]
                    try:
                        raw_lzma(payload, *DEFAULT, u0)
                        ok = True
                    except lzma.LZMAError:
                        ok = False
                    if not ok:
                        checked += 1
                        verdict = None
                        # 1. druge kombinacije
                        for lc in (0, 1, 2, 3, 4):
                            for lp in (0, 1, 2):
                                for pb in (0, 1, 2, 3, 4):
                                    for ds in (1 << 16, 1 << 20, 1 << 23):
                                        try:
                                            r = raw_lzma(payload, lc, lp, pb, ds, u0)
                                            if len(r) == u0:
                                                verdict = f"lzma1 raw lc{lc} lp{lp} pb{pb} dict{ds}"
                                                raise StopIteration
                                        except lzma.LZMAError:
                                            pass
                                        except StopIteration:
                                            raise
                    # gornji blok koristi izuzetak za prekid; uhvati ga
                    pass
            off += bs
    return {}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("atlas", type=Path)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()
    return probe(a.atlas, a.output, a.limit)


def probe(path: Path, output: Path, limit: int) -> int:
    size = path.stat().st_size
    off = 0
    outcome: Counter[str] = Counter()
    partial_bins: Counter[str] = Counter()
    samples: list[dict[str, object]] = []
    failing = 0
    with path.open("rb") as f:
        while True:
            f.seek(off); h = f.read(0x22)
            if len(h) < 0x22: break
            nl = h[0]
            if nl == 0 or nl > 15: break
            bs = struct.unpack_from("<I", h, 0x10)[0]
            if bs < 0x20 or off + bs > size: break
            if h[1:1 + nl] == b"CONTAINER" and h[0x20] == 3:
                f.seek(off); b = f.read(bs)
                cnt = b[0x21]
                pairs = [struct.unpack_from("<II", b, 0x22 + i * 8) for i in range(cnt)]
                d0 = 0x22 + cnt * 8
                c0, u0 = pairs[0]
                payload = b[d0:d0 + c0]
                try:
                    if len(raw_lzma(payload, *DEFAULT, u0)) != u0:
                        raise lzma.LZMAError("kratko")
                except lzma.LZMAError:
                    failing += 1
                    verdict = None
                    for lc in (0, 1, 2, 3, 4):
                        for lp in (0, 1, 2):
                            for pb in (0, 1, 2, 3, 4):
                                for ds in (1 << 16, 1 << 20, 1 << 24):
                                    if (lc, lp, pb, ds) == DEFAULT: continue
                                    try:
                                        if len(raw_lzma(payload, lc, lp, pb, ds, u0)) == u0:
                                            verdict = f"lzma1 raw lc{lc} lp{lp} pb{pb} dict{ds}"
                                    except lzma.LZMAError:
                                        pass
                                    if verdict: break
                                if verdict: break
                            if verdict: break
                        if verdict: break
                    if verdict is None:
                        try:
                            if len(lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(payload)) == u0:
                                verdict = "lzma alone"
                        except lzma.LZMAError:
                            pass
                    if verdict is None:
                        for wbits, tag in ((15, "zlib"), (-15, "raw deflate")):
                            try:
                                if len(zlib.decompress(payload, wbits)) == u0:
                                    verdict = tag
                                    break
                            except zlib.error:
                                pass
                    got = partial(payload, u0)
                    ratio = got / u0 if u0 else 0
                    partial_bins[f"{int(ratio * 10) * 10}%"] += 1
                    if verdict is None:
                        verdict = "neresen"
                    outcome[verdict] += 1
                    if len(samples) < 12:
                        samples.append({"offset": off, "block_size": bs, "chunks": pairs,
                                        "csize": c0, "usize": u0, "partial_bytes": got,
                                        "first16": payload[:16].hex(), "verdict": verdict,
                                        "field_c": struct.unpack_from("<I", b, 0x1c)[0]})
                    if limit and failing >= limit:
                        break
            off += bs
    report = {"file": str(path), "failing_blocks": failing,
              "verdicts": dict(outcome.most_common()),
              "partial_decode_ratio_bins": dict(sorted(partial_bins.items())),
              "samples": samples}
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "samples"}, indent=2, ensure_ascii=False))
    print(json.dumps(report["samples"][:4], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
