# Project status & continuation guide

Last updated: 2026-09-04. Start here to continue the work. This ties together
the detailed docs and says exactly what is done, what is next, and how to
verify. Run `python3 scripts/audit.py` at any time for a full green/red check.

## One-line state

The routing (PSD) conversion MIB → 3G Plus is complete and packaged into a
real MMI3GP SD-root. The XAC/POI layer's container and framing are proven;
its innermost content encoder is the remaining work. Nothing forges or
bypasses the device's signature/integrity check — that step is the owner's.

## Layer state

| Layer | State | Where |
|---|---|---|
| PSD (routing) | ✅ converted, `SRB.5_1.0.ATLAS` passes grammar/index/roundtrip | `out/orion_atlas_build_full/pkg/` |
| ATLAS container | ✅ writer, rebuilds original 5 GB PSD byte-identically | `docs/ATLAS_CONTAINER.md` |
| XAC/POI container (FLDB) | ✅ writer, byte-identical round-trip | `tools/fldb_container.py` |
| XAC inner-block framing | ✅ writer, 3977/3977 byte-identical | `tools/xac_inner.py` |
| XAC 4th-field question | ✅ resolved from firmware (informational, not a gate) | `docs/XAC_WRITER_NOTES.md` |
| XAC/POI innermost content | ⏳ next: encoder for ORTSNAMEN/PHONEME/VEKTORBLOCK | `docs/XAC_WRITER_NOTES.md` |
| LIT / TMC content | ⏳ container done, content writers not built | `docs/PKGDB_LAYERS.md` |
| TER / CTY | source has no MIB equivalent → keep original | — |
| SD-root assembly | ✅ PSD-only MMI3GP tree built | `out/SDCARD_MMI3GP_SRB/` |
| Device acceptance (signing) | ⛔ owner's step — not done here, not forged | `docs/FW_PROTECTION_MODEL.md` |

## The SD-root artifact

`out/SDCARD_MMI3GP_SRB/` is the original 6.36.0 MMI3GP release mirrored by
hardlink, with our converted PSD swapped in (PSD2/PSD3 and the original PSD
part dropped). Real new disk ≈ 32 MB. The aggregate `.pkg`, `.pkg.sig`,
`metainfo2.txt` and `DBInfo.txt` are **untouched** (same inode as the
original) and still describe the original content — so the unit will reject
this tree at its integrity/signature check. `README_SDCARD.txt` inside states
this. Making it consistent and signing it is the owner's separate step; this
repository never forges a CRC or signature.

## What to do next (XAC/POI content encoder)

The deep remaining piece. Read `docs/XAC_WRITER_NOTES.md` end to end first.
Concretely:

1. Decode the `.poi`/ORTSNAMEN sub-block table exactly from the firmware. The
   naive `(offset,size)×count` reading is wrong (a pair went out of bounds and
   one entry pointed into the header). The reader is `CXacDb::getGlobalPoi`/
   `getGlobalOrt`; decompilation saved at `~/mmi3g-atlas/poireader.txt`, and the
   parser `FUN_0825d954` / `FUN_08305560` still need to be read for the table
   layout.
2. Understand the `BUILD_INFO_TEXT` capability gate (`FUN_0825ecc8`): a
   generated XAC must carry a build-info block that passes its `check*` flags.
3. Reduce MIB POI (`psf_decode.py landmarks` + `GlobalPOIIndices.psf`) to a
   canonical record set; emit ORTSNAMEN/PHONEME/VEKTORBLOCK bodies; wrap tiles
   with `xac_inner.py` then `fldb_container.py build`; verify against original.

Pragmatic alternative: POI is an enhancement. A working, newer-routing SD can
keep the original XAC and skip this encoder entirely.

## Firmware analysis (Ghidra) — where the artifacts are

NavCore project: `~/mmi3g-atlas/ghidra_proj` (NavCoreProj), scripts in
`~/mmi3g-atlas/ghidra_scripts/`, headless via `analyzeHeadless ... -process
NavCore -noanalysis`. Saved dumps: `fldb_parser.txt` (FUN_080a7584, the FLDB
open/validate), `xac_decomp.txt` (192 XAC functions), `poireader.txt`
(CXacDb POI/ORT readers). The audit re-checks the FLDB magic directly against
NavCore at VA 0x083ccb54.

## Verify everything

```bash
export MMI3G_PKGDB=/path/to/8R0051884KL_6.36.0_2023/pkgdb
export NAVCORE_ELF=/path/to/extracted/mnt/ifs-root/usr/apps/NavCore
python3 scripts/audit.py          # 30 checks: repo, PSD, firmware, XAC, SD-root
python3 -m unittest discover -s tests
```

## Scope boundary (unchanged, firm)

Read-only RE and format conversion: yes. Producing correct converted content
and an honest package tree: yes. Forging CRCs, reusing/faking the publisher
signature, or any trick to make the device accept unsigned/modified content:
no — and such material is kept out of this repository (moved to
`~/mmi3g-atlas/device_install_excluded/`, never committed).
