#!/usr/bin/env python3
"""orion_block_writer.py — sastavljac ATLAS bloka i njegov round-trip dokaz.

Writer mora umeti da napravi blok bajt-identican originalu.  Zato se ovde
svaki originalni blok rastavi i ponovo sastavi, pa uporedi sa originalom.
Provera je podeljena na dva nezavisna nivoa, jer ne znace isto:

1. **Struktura** — blok se sastavlja iz procitanih polja i *originalnih*
   kompresovanih bajtova.  Ovo dokazuje da su ime, popuna, zaglavlje,
   chunk tabela, `data_offset`, popuna i terminator tacno reprodukovani.
   Tu se ocekuje bajt-identican rezultat.

2. **Codec** — payload se raspakuje pa ponovo spakuje istim parametrima.
   Bajt-identican rezultat ovde nije uslov ispravnosti: bitno je da nas
   izlaz raspakovan daje iste podatke.  Zato se meri i jedno i drugo, a
   kao uspeh se broji semanticki round-trip.

Ne dira se ulazni fajl.
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

TERMINATOR = bytes.fromhex("0123456789abcdeffedcba9876543210")
ALIGNMENT = 16
CODEC_STORED, CODEC_ZLIB, CODEC_LZMA = 1, 2, 3
LZMA_FILTERS = [{"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2,
                 "dict_size": 1 << 20}]


def align16(value: int) -> int:
    return (value + ALIGNMENT - 1) // ALIGNMENT * ALIGNMENT


def decompress(codec: int, data: bytes, expected: int) -> bytes:
    if codec == CODEC_STORED:
        return data[:expected]
    if codec == CODEC_ZLIB:
        return zlib.decompress(data)[:expected]
    engine = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=LZMA_FILTERS)
    return engine.decompress(data)[:expected]


def compress(codec: int, data: bytes) -> bytes:
    if codec == CODEC_STORED:
        return data
    if codec == CODEC_ZLIB:
        return zlib.compress(data, 9)
    engine = lzma.LZMACompressor(format=lzma.FORMAT_RAW, filters=LZMA_FILTERS)
    return engine.compress(data) + engine.flush()


def parse_block(block: bytes) -> dict[str, object]:
    name_length = block[0]
    name = block[1:1 + name_length]
    pad = block[1 + name_length:0x10]
    block_size = struct.unpack_from("<I", block, 0x10)[0]
    codec = block[0x20]
    if codec == CODEC_STORED:
        data_offset = 0x21
        chunks = None
        payload = block[data_offset:block_size - ALIGNMENT]
    else:
        count = block[0x21]
        data_offset = 0x22 + count * 8
        chunks = [struct.unpack_from("<II", block, 0x22 + i * 8) for i in range(count)]
        payload = block[data_offset:data_offset + sum(c for c, _ in chunks)]
    return {
        "name": name,
        "pad": pad,
        "block_size": block_size,
        "header": block[0x14:0x20],
        "codec": codec,
        "chunks": chunks,
        "data_offset": data_offset,
        "payload": payload,
        "fill": block[data_offset + len(payload):block_size - ALIGNMENT],
    }


def build_block(parsed: dict[str, object], payload: bytes,
                chunks: list[tuple[int, int]] | None = None) -> bytes:
    name = parsed["name"]
    out = bytearray()
    out.append(len(name))
    out += name
    out += parsed["pad"]
    out += struct.pack("<I", 0)          # velicina, popunjava se na kraju
    out += parsed["header"]
    out.append(parsed["codec"])
    if parsed["codec"] == CODEC_STORED:
        block_size = align16(0x21 + len(payload) + ALIGNMENT)
    else:
        chunks = list(chunks if chunks is not None else parsed["chunks"])
        out.append(len(chunks))
        for compressed_size, raw_size in chunks:
            out += struct.pack("<II", compressed_size, raw_size)
        block_size = align16(len(out) + len(payload) + ALIGNMENT)
    out += payload
    out += bytes(parsed["fill"][:block_size - ALIGNMENT - len(out)]) \
        if len(parsed["fill"]) >= block_size - ALIGNMENT - len(out) \
        else bytes(parsed["fill"]) + b"\xcc" * (block_size - ALIGNMENT - len(out)
                                                - len(parsed["fill"]))
    out += TERMINATOR
    struct.pack_into("<I", out, 0x10, len(out))
    return bytes(out)


def run(path: Path, output: Path, limit: int) -> dict[str, object]:
    file_size = path.stat().st_size
    offset = index = 0
    stats = Counter()
    failures: list[str] = []
    size_delta: Counter[str] = Counter()

    with path.open("rb") as source:
        while limit == 0 or index < limit:
            source.seek(offset)
            head = source.read(0x20)
            if len(head) < 0x20:
                break
            name_length = head[0]
            if name_length == 0 or name_length > 0x0F:
                break
            block_size = struct.unpack_from("<I", head, 0x10)[0]
            if block_size < 0x20 or offset + block_size > file_size:
                break
            source.seek(offset)
            block = source.read(block_size)
            index += 1
            name = block[1:1 + name_length]
            if name != b"CONTAINER":
                offset += block_size
                continue

            parsed = parse_block(block)
            stats["blokova"] += 1

            rebuilt = build_block(parsed, parsed["payload"])
            if rebuilt == block:
                stats["struktura bajt-identicna"] += 1
            else:
                if len(failures) < 20:
                    failures.append(f"@0x{offset:x}: struktura se razlikuje")

            codec = parsed["codec"]
            raw_size = parsed["chunks"][0][1] if parsed["chunks"] else len(parsed["payload"])
            try:
                decoded = decompress(codec, parsed["payload"], raw_size)
            except Exception as error:                        # noqa: BLE001
                stats["payload se ne raspakuje"] += 1
                if len(failures) < 20:
                    failures.append(f"@0x{offset:x}: {type(error).__name__}")
                offset += block_size
                continue
            stats["payload raspakovan"] += 1

            recompressed = compress(codec, decoded)
            if recompressed == parsed["payload"]:
                stats["codec bajt-identican"] += 1
            try:
                again = decompress(codec, recompressed, raw_size)
            except Exception:                                 # noqa: BLE001
                again = None
            if again == decoded:
                stats["codec semanticki round-trip"] += 1
            else:
                if len(failures) < 20:
                    failures.append(f"@0x{offset:x}: semanticki round-trip pao")

            delta = len(recompressed) - len(parsed["payload"])
            size_delta["manji" if delta < 0 else "isti" if delta == 0 else "veci"] += 1

            offset += block_size
            if index % 5000 == 0:
                print(f"  ...{index} blokova", flush=True)

    report = {
        "file": str(path),
        "blocks_seen": index,
        "checks": dict(stats),
        "recompressed_size_vs_original": dict(size_delta.most_common()),
        "failure_count": len(failures),
        "failure_samples": failures[:20],
        "boundary": (
            "Bajt-identican codec izlaz nije uslov ispravnosti; nas LZMA "
            "koder nije isti kao originalni. Uslov je semanticki round-trip "
            "i tacna struktura bloka."
        ),
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = []
    for item in sorted(output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("atlas", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    report = run(args.atlas, args.output, args.limit)
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 1 if report["failure_count"] else 0


if __name__ == "__main__":
    sys.exit(main())
