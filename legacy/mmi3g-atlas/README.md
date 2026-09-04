# legacy/mmi3g-atlas — the first research pass (31 Aug – 1 Sep 2026)

These are the scripts and the log from the first days, when nothing about
the MMI 3G Plus map format was known. They are kept exactly as they were
used, because `DOCS.md` reads as a lab notebook: each section says what was
tried, what came out, and what was wrong the day before.

The later, stricter tooling lives in `../../tools/`. If you want to build or
verify an `.ATLAS`, use that. If you want to understand how the format was
found, read this.

## Files

| File | Purpose |
|---|---|
| `DOCS.md` | The research log (Serbian): goal and scope, unit configuration, firmware findings with addresses, the `.ATLAS` format as it was decoded step by step, integrity chain, repack test, the discovery of the MIB source. |
| `ifs_tool.py` | QNX IFS image reader with a pure-Python LZO1X decompressor. `info`, `unpack`, `ls`, `extract`. |
| `atlas_recon.py` | First-contact recon on any binary: entropy, header dump with sector interpretation, strings, coordinate search, period detection, diff. |
| `atlas_blocks.py` | Block-chain parser for Orion `.ATLAS`: `scan`, `block`, `decode`, `walk`, `unpack`, `tiles`, `stats`. |
| `atlas_bits.py` | Bit-level reader for column codec 3 (5-bit width header). |
| `atlas_export.py` | Export of decoded PSD point columns to GeoJSON. This is what produced the first recognisable street grids. |
| `nds_names.py` | Extracts plain UTF-8 street and place names from a MIB `.psf` file. |
| `ghidra_scripts/*.java` | Headless Ghidra probes against NavCore and `vdev-logvolmgr`. They write their output next to a `~/mmi3g-atlas/` working directory. |

## Conclusions that were later corrected

Read `DOCS.md` with these in mind. Each was corrected by a script in
`../../tools/` and the corrected version is what `docs/` states.

| In `DOCS.md` | Corrected to | Where |
|---|---|---|
| LZMA dictionary 64 KiB; 835 PSD3 blocks "corrupt" | dictionary is 1 MiB; no block is corrupt | `docs/ATLAS_CONTAINER.md`, `tools/orion_lzma_failure_probe.py` |
| Longitude offset ≈ 80° | 78.25 ± 0.05°, measured on land/water and city hit counts | `DOCS.md` §6.10r itself, then superseded by the exact block key formula in `tools/orion_tile_formula_verify.py` |
| MIB `.psf` has no compression | PSF60 uses LZMA-Alone and zlib per stream; the sampled region was the uncompressed name table | `docs/PSF60_FORMAT.md`, `tools/psf_decode.py` |
| Heights column read as u16 | third column of the triple is not the same type in every block | handled by the schema-driven reader in `tools/orion_psd_reference_profile.py` |
| `.ATLAS` index unknown | INDEX tree lives in part 0 only; PSD3 is part 2 | `docs/ATLAS_CONTAINER.md` |

## Running

All scripts are Python 3 standard library. Paths to firmware and map files
are given as arguments; the Ghidra scripts expect the NavCore project at
`~/mmi3g-atlas/ghidra_proj` (override by editing the output path or setting
the project up there).
