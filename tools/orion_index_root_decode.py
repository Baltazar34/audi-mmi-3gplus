#!/usr/bin/env python3
"""orion_index_root_decode.py — koren INDEX stabla i REVISION blok.

Listovi (nivo 2) su dokazani u `orion_index_decode.py`.  Ovde se proverava
hipoteza da koren (nivo 1) ima isti raspored, ali da mu stavke pokazuju na
same INDEX listove:

  * offset/velicina korenske stavke i == offset/velicina i-tog lista;
  * separator korena i == prvi separator lista i+1  (ili poslednji lista i).

REVISION blok se samo dekodira polje po polje i poredi izmedju delova; nista
se ne imenuje bez dokaza.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orion_index_decode import decode_index_block, iter_blocks, read_part_header  # noqa: E402

import mmap  # noqa: E402


def run(paths: list[Path], output: Path) -> dict[str, object]:
    parts = sorted((read_part_header(p) for p in paths), key=lambda i: i["part_index"])
    part0 = parts[0]
    handle = part0["path"].open("rb")
    view = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        revision = None
        root = None
        leaves = []
        for offset, name, size in iter_blocks(view, part0["part_size"]):
            if name == b"CONTAINER":
                break
            if name == b"REVISION":
                revision = {"offset": offset, "size": size,
                            "raw_0x18_0x30": bytes(view[offset + 0x18:offset + 0x30]).hex(" "),
                            "u16_0x18": struct.unpack_from("<H", view, offset + 0x18)[0],
                            "u32_0x1c": struct.unpack_from("<I", view, offset + 0x1C)[0],
                            "u32_0x20": struct.unpack_from("<I", view, offset + 0x20)[0],
                            "u32_0x24": struct.unpack_from("<I", view, offset + 0x24)[0]}
            elif name == b"INDEX":
                decoded = decode_index_block(view, offset, size)
                decoded["block_offset"] = offset
                decoded["block_size"] = size
                if decoded["level"] == 1:
                    root = decoded
                else:
                    leaves.append(decoded)

        checks = {}
        details = []
        if root is not None:
            n = len(leaves)
            offs, sizes, seps = root["offsets"], root["sizes"], root["separators"]
            checks["root_entries"] = root["entries"]
            checks["leaf_count"] = n
            checks["root_offsets_equal_leaf_offsets"] = sum(
                1 for i in range(min(n, len(offs))) if offs[i] == leaves[i]["block_offset"])
            checks["root_sizes_equal_leaf_sizes"] = sum(
                1 for i in range(min(n, len(sizes))) if sizes[i] == leaves[i]["block_size"])
            first_of_next = sum(
                1 for i in range(min(n - 1, len(seps)))
                if seps[i] == leaves[i + 1]["separators"][0])
            last_of_this = sum(
                1 for i in range(min(n - 1, len(seps)))
                if seps[i] == leaves[i]["separators"][-1])
            checks["root_sep_equals_first_sep_of_next_leaf"] = first_of_next
            checks["root_sep_equals_last_sep_of_this_leaf"] = last_of_this
            # hipoteza: separator korena i == zaglavlje PRVOG bloka lista i+1
            def resolve(g):
                for item in parts:
                    local = g - item["preceding_size"]
                    if 0 <= local < item["part_size"]:
                        return item, local
                return None, None
            opened = {}
            hit = 0
            for i in range(min(n - 1, len(seps))):
                first_block = leaves[i + 1]["offsets"][0]
                item, local = resolve(first_block)
                if item is None:
                    continue
                if item["path"] not in opened:
                    fh = item["path"].open("rb")
                    opened[item["path"]] = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                v = opened[item["path"]]
                fa = struct.unpack_from("<H", v, local + 0x18)[0]
                fb = struct.unpack_from("<H", v, local + 0x1a)[0]
                fc = struct.unpack_from("<I", v, local + 0x1c)[0]
                if seps[i] == (fa, (fc << 8) | (fb >> 8)):
                    hit += 1
            for v in opened.values():
                v.close()
            checks["root_sep_equals_header_of_first_block_of_next_leaf"] = hit
            checks["root_sep_expected"] = min(n - 1, len(seps))
            # sta je iza stvarnih stavki korena
            tail = [(offs[i], sizes[i]) for i in range(n, len(offs))]
            checks["root_tail_entries"] = len(tail)
            checks["root_tail_repeats_last"] = all(t == (offs[n - 1], sizes[n - 1]) for t in tail)
            for i in range(min(4, n)):
                details.append({"i": i, "root_offset": offs[i], "leaf_offset": leaves[i]["block_offset"],
                                "root_sep": seps[i] if i < len(seps) else None,
                                "leaf_first_sep": leaves[i]["separators"][0],
                                "leaf_last_sep": leaves[i]["separators"][-1]})
        report = {"revision": revision, "root_checks": checks, "root_detail": details,
                  "revision_pointer_hint": (
                      "REVISION u32 na +0x1c/+0x20 poredi se sa offsetom korena/prvog lista")}
        if revision and root:
            report["revision_u32_0x1c_equals_root_offset"] = revision["u32_0x1c"] == root["block_offset"]
            report["revision_u32_0x1c_equals_root_size"] = revision["u32_0x1c"] == root["block_size"]
            report["revision_u32_0x20_equals_root_offset"] = revision["u32_0x20"] == root["block_offset"]
    finally:
        view.close(); handle.close()
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}"
             for p in sorted(output.iterdir()) if p.is_file() and p.name != "CHECKSUMS.sha256"]
    (output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")
    return report


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("parts", type=Path, nargs="+")
    ap.add_argument("--output", type=Path, required=True)
    a = ap.parse_args()
    print(json.dumps(run(a.parts, a.output), indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
