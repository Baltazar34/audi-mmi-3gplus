#!/usr/bin/env python3
"""orion_conf_write.py — `.conf` opis ATLAS fajla za pkgdb.

Format je preuzet iz originalnog `PSD3.conf`:

    [file]
    name=<ime>
    size=<bajtova>
    media=IsoImage
    MD5=<md5 celog fajla>
    check=qa,100,<md5 prvih 100 KiB>,<md5 100 KiB od size//2>,<treci>
    checkcrc=<crc nad .conf-om>
    [/file]

Sta je dokazano (self-test nad originalnim PSD3): `MD5` i prva dva
quick-check MD5 se reprodukuju tacno.  Treci quick-check MD5 i `checkcrc`
nisu reprodukovani; Harman dokumentacija kaze da je MD5 primaran a CRC32
"for testing only".  Zato se `check=` i `checkcrc=` upisuju samo ako su
prosledjeni (`--check-third`, `--checkcrc`), inace se izostavljaju i to se
jasno belezi u izvestaju.  Ova granica ostaje otvorena do device testa.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

QUICK = 100 * 1024


def md5_of(path: Path, start: int = 0, length: int | None = None) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        f.seek(start)
        remaining = length
        while True:
            chunk = f.read(1 << 20 if remaining is None else min(1 << 20, remaining))
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
                if remaining <= 0:
                    break
    return h.hexdigest()


def describe(path: Path) -> dict[str, object]:
    size = path.stat().st_size
    return {"name": path.name, "size": size, "md5": md5_of(path),
            "quick1": md5_of(path, 0, QUICK), "quick2": md5_of(path, size // 2, QUICK)}


def selftest(conf: Path, atlas: Path) -> dict[str, object]:
    text = conf.read_text(errors="replace")
    md5 = re.search(r"MD5=([0-9a-f]{32})", text).group(1)
    size = int(re.search(r"size=(\d+)", text).group(1))
    check = re.search(r"check=qa,(\d+),([0-9a-f]{32}),([0-9a-f]{32}),([0-9a-f]{32})", text)
    d = describe(atlas)
    return {"size_match": d["size"] == size, "md5_match": d["md5"] == md5,
            "quick1_match": bool(check) and d["quick1"] == check.group(2),
            "quick2_match": bool(check) and d["quick2"] == check.group(3),
            "quick3_reproduced": False, "checkcrc_reproduced": False,
            "quick_param": check.group(1) if check else None}


def render(template: str, d: dict[str, object], third: str | None, checkcrc: str | None) -> str:
    out = []
    for line in template.splitlines():
        if line.startswith("name=") and not line.startswith("name=PSD"):
            line = f"name={d['name']}"
        elif line.startswith("size="):
            line = f"size={d['size']}"
        elif line.startswith("MD5="):
            line = f"MD5={d['md5']} "
        elif line.startswith("check="):
            if third is None:
                continue
            line = f"check=qa,100,{d['quick1']},{d['quick2']},{third}"
        elif line.startswith("checkcrc="):
            if checkcrc is None:
                continue
            line = f"checkcrc={checkcrc}"
        out.append(line)
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("selftest"); t.add_argument("conf", type=Path); t.add_argument("atlas", type=Path)
    w = sub.add_parser("write"); w.add_argument("atlas", type=Path); w.add_argument("--template", type=Path, required=True)
    w.add_argument("--output", type=Path, required=True); w.add_argument("--check-third"); w.add_argument("--checkcrc")
    w.add_argument("--name", help="override the ATLAS filename written to the configuration")
    a = ap.parse_args()
    if a.cmd == "selftest":
        print(json.dumps(selftest(a.conf, a.atlas), indent=2)); return 0
    d = describe(a.atlas)
    if a.name:
        d["name"] = a.name
    text = render(a.template.read_text(errors="replace"), d, a.check_third, a.checkcrc)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(text)
    print(json.dumps({"written": str(a.output), **d, "check_line_written": a.check_third is not None,
                      "checkcrc_written": a.checkcrc is not None}, indent=2)); return 0


if __name__ == "__main__":
    sys.exit(main())
