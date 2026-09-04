#!/usr/bin/env python3
"""audit.py — full-project audit: repo hygiene, generated-PSD integrity,
firmware cross-check, XAC framing, and SD-root completeness (missing files).

Every check prints PASS / FAIL / SKIP (skip = the local map/firmware input is
not present). Exit code is non-zero if any check FAILs. Inputs via env vars:
MMI3G_PKGDB, NAVCORE_ELF, and the SD-root/build under out/.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILS: list[str] = []
LINES: list[str] = []


def check(name: str, ok: bool | None, detail: str = "") -> None:
    tag = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    if ok is False:
        FAILS.append(name)
    LINES.append(f"  [{tag}] {name}{(' — ' + detail) if detail else ''}")


def md5(path: Path) -> str:
    h = hashlib.md5()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def section(title: str) -> None:
    LINES.append(f"\n== {title}")


# ---------------------------------------------------------------- 1. repo hygiene
def audit_repo() -> None:
    section("1. Repo hygiene")
    r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                       cwd=ROOT, capture_output=True, text=True)
    m = re.search(r"Ran (\d+) tests", r.stderr)
    check("unit tests pass", r.returncode == 0, (m.group(0) if m else "") )

    tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    personal, tmp_defaults = [], []
    for rel in tracked:
        p = ROOT / rel
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if re.search(r"/(Users|home)/[A-Za-z0-9._-]+/", t):  # a personal home dir
            personal.append(rel)
        if "/private/tmp/" in t or re.search(r"(?<![\w/])/tmp/", t):
            tmp_defaults.append(rel)
    check("no personal home paths in tracked files", not personal, ", ".join(personal[:5]))
    # /private/tmp defaults are benign (documented example/fallback paths), reported not failed
    LINES.append(f"  [INFO] generic /tmp default paths (benign): {len(tmp_defaults)} files")

    banned = ["fdefcrc.py", "mmi3gp_psd_padding.py", "metainfo_crc.py",
              "package_device_test.py", "find_sig_gates.java"]
    present = [b for b in banned if any(b in t for t in tracked)]
    check("circumvention tools absent from repo", not present, ", ".join(present))

    gi = (ROOT / ".gitignore").read_text()
    need = ["*.ATLAS", "*.psf", "*.db", "*.7z", "out/"]
    check("gitignore covers payloads", all(n in gi for n in need),
          "missing " + ", ".join(n for n in need if n not in gi))


# ------------------------------------------------------- 2. generated PSD integrity
def audit_psd() -> Path | None:
    section("2. Generated PSD integrity")
    pkg = ROOT / "out" / "orion_atlas_build_full" / "pkg"
    atlas = pkg / "SRB.5_1.0.ATLAS"
    conf = pkg / "PSD.conf"
    if not atlas.exists():
        check("PSD build present", None, "run the pipeline first")
        return None
    check("PSD build present", True, f"{atlas.stat().st_size} B")

    out = ROOT / "out" / "_audit_grammar"
    r = subprocess.run([sys.executable, "tools/orion_block_grammar_verify.py", str(atlas),
                        "--output", str(out)], cwd=ROOT, capture_output=True, text=True)
    try:
        import json
        rep = json.loads((out / "report.json").read_text())
        check("PSD grammar: every byte explained",
              rep.get("not_explained") == 0 and rep.get("file_coverage") == 1.0,
              f"not_explained={rep.get('not_explained')} coverage={rep.get('file_coverage')}")
    except Exception as e:
        check("PSD grammar", False, str(e)[:60])

    if conf.exists():
        txt = conf.read_text(errors="replace")
        m = re.search(r"MD5=([0-9a-f]{32})", txt)
        s = re.search(r"size=(\d+)", txt)
        actual = md5(atlas)
        check("PSD.conf MD5 matches the actual ATLAS", bool(m) and m.group(1) == actual,
              f"conf={m.group(1) if m else '-'} actual={actual}")
        check("PSD.conf size matches the actual ATLAS",
              bool(s) and int(s.group(1)) == atlas.stat().st_size)
        check("PSD.conf carries no forged check/checkcrc",
              "check=" not in txt and "checkcrc=" not in txt)
    return pkg


# -------------------------------------------------------------- 3. firmware cross-check
def audit_firmware() -> None:
    section("3. Firmware cross-check (NavCore)")
    nav = os.environ.get("NAVCORE_ELF")
    cands = [Path(nav)] if nav else []
    cands += list((Path.home() / "mmi3g-atlas" / "extracted").rglob("NavCore"))
    nc = next((p for p in cands if p.exists()), None)
    if nc is None:
        check("NavCore available", None, "set NAVCORE_ELF to cross-check")
        return
    data = nc.read_bytes()
    IMAGE_BASE = 0x08040000
    off = 0x083CCB54 - IMAGE_BASE
    check("'FLDB' magic present at documented VA 0x083ccb54",
          data[off:off + 4] == b"FLDB", f"found {data[off:off+4]!r}")
    for s in (b"ORTSNAMEN", b"VEKTORBLOCK", b"CXacDb::getGlobalPoi", b"BUILD_INFO_TEXT"):
        check(f"firmware string present: {s.decode()}", s in data)
    # documented parser + notes artifacts
    for art in ("fldb_parser.txt", "xac_decomp.txt", "poireader.txt"):
        check(f"decompilation artifact saved: {art}",
              (Path.home() / "mmi3g-atlas" / art).exists())


# ---------------------------------------------------------- 4. XAC framing over whole DB
def audit_xac_framing() -> None:
    section("4. XAC inner-block framing (whole DB)")
    pkgdb = os.environ.get("MMI3G_PKGDB")
    xacdb = None
    if pkgdb:
        for name in ("XAC/kN221EUx01_0.db",):
            p = Path(pkgdb) / name
            if p.exists():
                xacdb = p
    if xacdb is None:
        check("original XAC available", None, "set MMI3G_PKGDB to validate framing")
        return
    sys.path.insert(0, str(ROOT / "tools"))
    from xac_inner import parse, rebuild  # noqa
    f = open(xacdb, "rb")
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    hs, fc, es = struct.unpack_from("<I8xII", mm, 0)
    diro = hs + 8
    tot = ok = 0
    for i in range(fc):
        c = diro + i * es
        _, o, s = struct.unpack_from("<III", mm, c + 24)
        if s < 0x18:
            continue
        body = bytes(mm[o:o + s])
        try:
            rebuilt, _ = rebuild(body)
            tot += 1
            ok += rebuilt == body
        except Exception:
            tot += 1
    check("every XAC inner body round-trips byte-identically", ok == tot and tot > 0,
          f"{ok}/{tot}")


# ------------------------------------------------------- 5. SD-root completeness
def audit_sdroot() -> None:
    section("5. SD-root completeness (missing files)")
    sd = ROOT / "out" / "SDCARD_MMI3GP_SRB"
    pkgdb = os.environ.get("MMI3G_PKGDB")
    if not sd.exists():
        check("SD-root present", None, "build_sdcard.py not run")
        return
    rel = Path(pkgdb).parent if pkgdb else None
    check("SD-root present", True, str(sd))

    # our PSD present, aggregate integrity files present
    check("our PSD present in SD", (sd / "pkgdb/PSD/SRB.5_1.0.ATLAS").exists())
    for f in ("metainfo2.txt", "DBInfo.txt",
              "pkgdb/MMI3GP_ECE_Hi_R_6_36_0.pkg", "pkgdb/MMI3GP_ECE_Hi_R_6_36_0.pkg.sig"):
        check(f"aggregate file present: {f}", (sd / f).exists())
    # dropped files really gone
    for f in ("pkgdb/PSD2", "pkgdb/PSD3",
              "pkgdb/PSD/APN221EU22093P1664a.5_1.0.ATLAS"):
        check(f"dropped as intended: {f}", not (sd / f).exists())
    # manifest + readme
    check("manifest + readme present",
          (sd / "SDCARD_MANIFEST.json").exists() and (sd / "README_SDCARD.txt").exists())

    if rel and rel.exists():
        dropped_prefixes = ("pkgdb/PSD2", "pkgdb/PSD3")
        dropped_exact = {"pkgdb/PSD/APN221EU22093P1664a.5_1.0.ATLAS"}
        missing = []
        for p in rel.rglob("*"):
            if not p.is_file():
                continue
            rp = p.relative_to(rel).as_posix()
            if rp.startswith(dropped_prefixes) or rp in dropped_exact:
                continue
            if not (sd / rp).exists():
                missing.append(rp)
        check("no original file missing from SD (except intentional drops)",
              not missing, f"{len(missing)} missing: " + ", ".join(missing[:5]))
        # aggregate integrity files must be identical to original (untouched)
        untouched = all(
            (sd / f).exists() and (rel / f).exists()
            and (sd / f).stat().st_ino == (rel / f).stat().st_ino
            for f in ("metainfo2.txt", "DBInfo.txt",
                      "pkgdb/MMI3GP_ECE_Hi_R_6_36_0.pkg",
                      "pkgdb/MMI3GP_ECE_Hi_R_6_36_0.pkg.sig")
        )
        check("aggregate integrity files untouched (same inode as original)", untouched)
    else:
        check("compare SD-root against original release", None, "MMI3G_PKGDB not set")


def main() -> int:
    LINES.append("AUDI MMI 3G+ PROJECT AUDIT")
    audit_repo()
    audit_psd()
    audit_firmware()
    audit_xac_framing()
    audit_sdroot()
    LINES.append("")
    total = sum(1 for l in LINES if "[PASS]" in l or "[FAIL]" in l or "[SKIP]" in l)
    npass = sum(1 for l in LINES if "[PASS]" in l)
    nskip = sum(1 for l in LINES if "[SKIP]" in l)
    LINES.append(f"SUMMARY: {npass} pass, {len(FAILS)} fail, {nskip} skip, of {total} checks")
    if FAILS:
        LINES.append("FAILURES: " + ", ".join(FAILS))
    print("\n".join(LINES))
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
