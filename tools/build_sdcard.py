#!/usr/bin/env python3
"""build_sdcard.py — assemble an SD-card root by swapping in converted map files.

It mirrors an original release tree (hardlinks by default, so a 38 GB package
costs almost no extra space), then overlays our own generated layer files and
optionally drops stale original parts.  It does exactly what "menjas fajlove
samo" means: it replaces map data files and nothing else.

Hard rule — this tool never forges or touches an integrity/signature file.
It refuses to overlay or drop any `*.pkg`, `*.pkg.sig`, root `metainfo2.txt`,
`DBInfo.txt`, `config.nfm` or `build1`.  Those stay as the original bytes.  As
a result the produced tree is a content swap, not an installable update: its
aggregate metadata and signature still describe the original content, so the
device will reject it until it is (legitimately) re-described and signed.  That
step is deliberately out of scope here.

Every overlaid file is hashed (SHA-256) into a manifest, and a README states
plainly what was changed and what remains the user's step.

Usage:
    python3 tools/build_sdcard.py \
        --release-root "<original release>" --output out/SDCARD \
        --overlay out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS:pkgdb/PSD/SRB.5_1.0.ATLAS \
        --overlay out/orion_atlas_build_full/pkg/PSD.conf:pkgdb/PSD/PSD.conf \
        --drop pkgdb/PSD/APN221EU22093P1664a.5_1.0.ATLAS \
        --drop pkgdb/PSD2 --drop pkgdb/PSD3
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

# Files whose contents are integrity/signature/aggregate metadata.  This tool
# must never create, overlay or drop these; they are mirrored verbatim.
PROTECTED_SUFFIXES = (".pkg", ".sig")
PROTECTED_NAMES = {"metainfo2.txt", "dbinfo.txt", "config.nfm", "build1"}


def is_protected(rel: str) -> bool:
    name = Path(rel).name.lower()
    if name.endswith(".pkg") or name.endswith(".pkg.sig") or name.endswith(".sig"):
        return True
    # Only the ROOT aggregate metadata is protected; per-layer *.conf we generate
    # ourselves (honest description of our own file) is allowed.
    if name in PROTECTED_NAMES and Path(rel).parent.name in ("", ".") :
        return True
    if name in PROTECTED_NAMES and "/" not in rel.strip("/").replace(os.sep, "/"):
        return True
    return False


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def mirror(release_root: Path, output: Path, use_copy: bool) -> tuple[int, int]:
    files = links = 0
    for src in sorted(release_root.rglob("*")):
        rel = src.relative_to(release_root)
        dst = output / rel
        if src.is_dir():
            dst.mkdir(parents=True, exist_ok=True)
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        if use_copy:
            shutil.copy2(src, dst)
        else:
            try:
                os.link(src, dst)
                links += 1
            except OSError:
                shutil.copy2(src, dst)
        files += 1
    return files, links


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--release-root", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--overlay", action="append", default=[], metavar="SRC:DEST",
                    help="place SRC at output/DEST (DEST is release-relative)")
    ap.add_argument("--drop", action="append", default=[], metavar="REL",
                    help="remove output/REL from the mirror (file or dir)")
    ap.add_argument("--copy", action="store_true", help="real copy instead of hardlink")
    args = ap.parse_args()

    if not args.release_root.is_dir():
        raise SystemExit(f"release root not found: {args.release_root}")

    # Enforce the hard rule before doing any work.
    for spec in args.overlay:
        dest = spec.split(":", 1)[1] if ":" in spec else spec
        if is_protected(dest):
            raise SystemExit(f"refusing to overlay a protected integrity/signature file: {dest}")
    for rel in args.drop:
        if is_protected(rel):
            raise SystemExit(f"refusing to drop a protected integrity/signature file: {rel}")

    args.output.mkdir(parents=True, exist_ok=True)
    files, links = mirror(args.release_root, args.output, args.copy)

    overlaid, dropped = [], []
    for spec in args.overlay:
        src_s, dest_s = spec.split(":", 1)
        src, dest = Path(src_s), args.output / dest_s
        if not src.is_file():
            raise SystemExit(f"overlay source not found: {src}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            dest.unlink()
        shutil.copy2(src, dest)  # our generated files are always real copies
        overlaid.append({"dest": dest_s, "bytes": dest.stat().st_size, "sha256": sha256(dest)})
    for rel in args.drop:
        target = args.output / rel
        if target.is_dir():
            shutil.rmtree(target)
            dropped.append(rel + "/")
        elif target.exists():
            target.unlink()
            dropped.append(rel)

    manifest = {
        "release_root": str(args.release_root),
        "output": str(args.output),
        "mode": "copy" if args.copy else "hardlink",
        "mirrored_files": files,
        "hardlinks": links,
        "overlaid": overlaid,
        "dropped": dropped,
        "integrity_files_touched": [],
        "note": "content swap only; .pkg/.pkg.sig and root metainfo2/DBInfo are the "
                "original bytes, so this tree is NOT installable until it is "
                "legitimately re-described and signed. No CRC/signature was forged.",
    }
    (args.output / "SDCARD_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (args.output / "README_SDCARD.txt").write_text(
        "This SD-card root was assembled by build_sdcard.py.\n\n"
        "What changed: the map data files listed in SDCARD_MANIFEST.json were\n"
        "replaced with locally converted content. Everything else is the\n"
        "original release, mirrored by hardlink.\n\n"
        "What was NOT touched: the signed package (*.pkg / *.pkg.sig) and the\n"
        "aggregate metainfo2.txt / DBInfo.txt. They still describe the ORIGINAL\n"
        "content. No checksum or signature was recomputed or forged.\n\n"
        "Consequence: the unit will reject this tree at its integrity/signature\n"
        "check. Making it consistent and signing it is a separate, deliberate\n"
        "step handled by the owner, not by this tool.\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
