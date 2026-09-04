# Audi MMI 3G Plus — map format research and MIB → 3G+ converter

Cars with the Audi **MMI 3G Plus** navigation unit (A6/A7/A8/Q3 of the C7 era,
firmware branch HN+R) received their last official map release in 2023.
Newer Audi/VW units on the **MIB** platform still get maps every year.

This repository documents both map formats, reconstructed read-only from the
firmware that reads them, and contains a complete, verified toolchain that
takes a MIB map dataset and produces a structurally valid MMI 3G Plus
`.ATLAS` routing database. Everything was done on a Mac, on copies of files.
The car was never touched.

Serbian version of this page: [README.sr.md](README.sr.md). Most of the
detailed documentation in `docs/` is in Serbian; the entry points and the
tool index are in English.

## What works, what does not

| Stage | Status |
|---|---|
| Unpack 3G Plus firmware (QNX IFS, own LZO1X decompressor) and locate the map parsers | done |
| Unpack MIB (MHI2) firmware (QNX6 image) and locate the PSF parser | done |
| Orion `.ATLAS` format: header, block chain, LZMA1 raw codec, column schema, bit-level column codecs, spatial block key, INDEX tree | done, byte-for-byte proven |
| Read the newer MIB `PSF60` map: clusters, topology, geometry, names, languages, road attributes, AdvancedRouting/ADAS framing | done over the full Serbia/Montenegro/Kosovo dataset |
| Write Orion objects (PointLlh, Node/Edge, clothoid centerlines, properties) | done, self-validating |
| Write a complete `.ATLAS` file (HEADER / REVISION / INDEX / CONTAINER blocks) plus its `.conf` | done; the writer rebuilds the original 5 GB PSD database byte-identically |
| Full conversion of one MIB region into a 3G Plus routing database | done: `SRB.5_1.0.ATLAS`, 32.3 MB, passes every verifier |
| Other pkgdb layers (3D cities, terrain, text, TMC, POI) | formats decoded, per-layer writers not built |
| Semantics of AdvancedRouting / ADAS record internals, VidTable and XAC name text | partly open, see status doc |
| Install the generated package on the car | **not possible without the publisher's signature**, see below |

Numbers for the full Serbia run:

| Item | Value |
|---|---|
| MIB source edges / nodes | 838,433 / 717,730 |
| Spatial cells / CONTAINER blocks | 3,877 / 3,915 |
| Generated `.ATLAS` | 32.3 MB, one part, two INDEX leaves |
| Original PSD round-trip (3 parts, 5.04 GB) | 254,828 blocks, 0 deviations |
| Unit tests | 146, all passing |

## Where it stops, and why

The 3G Plus unit checks a map package only during installation, in the
software-download flow. The check is a chain: package signature (`.pkg.sig`,
verified by the `cryptomanager` process with a public key on the device),
CRC of each `.conf`, MD5 of each `.ATLAS`, and the FSC licence bound to the
map part number. A new map means a new MD5, a new `.conf` CRC, and a package
that only the publisher can sign.

This project reproduces every link of that chain that can be reproduced
(MD5, quick-check MD5, `.conf` layout) and documents the rest as it is in the
firmware. It does **not** patch firmware, does not forge signatures, does not
use the factory "skip" switches and does not ship an FSC workaround. Read
[docs/FW_PROTECTION_MODEL.md](docs/FW_PROTECTION_MODEL.md) before asking.

## What is not in this repository

- No map data. Not the original 3G Plus release, not the MIB dataset, not
  the generated `.ATLAS`. All of it is licensed content. `.gitignore`
  refuses the relevant extensions.
- No firmware images and no extracted binaries. The docs quote addresses,
  strings and decompiled logic; you need your own copy of the firmware to
  reproduce the evidence with the `run_*_re.py` runners.
- No credentials, no download links to third-party dumps.

## Quick start

Requirements: Python 3.10 or newer, standard library only. Optional:
`7z` (reading archives directly), Ghidra 11+ (regenerating firmware evidence).

```bash
git clone <this repo> audi-mmi && cd audi-mmi
python3 -m unittest discover -s tests
```

Point the tools at your own inputs through environment variables. Full
list and file identities (names, sizes, SHA-256) are in
[docs/INPUT_INVENTORY.md](docs/INPUT_INVENTORY.md).

```bash
export MIB_MAP_ROOT=/path/to/Mib1/NavDB/SerbiaMontenegroKosovo_eu/0/default
export MMI3G_PKGDB=/path/to/8R0051884KL_6.36.0_2023/pkgdb
export NAVCORE_ELF=/path/to/extracted/usr/apps/NavCore
```

First things to try:

```bash
# MIB side: what is inside a PSF file
python3 tools/psf_decode.py inspect "$MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf"

# 3G Plus side: schemas inside an original Orion layer
python3 tools/orion_layer_survey.py "$MMI3G_PKGDB/PSD3/APN221EU22093P1664a.5_1.2.ATLAS" --limit 5

# The whole container verification pipeline against the original PSD
python3 tools/run_container_pipeline.py tools/orion_container_pipeline.json \
  --state out/orion_container_pipeline_state.json --jobs 3
```

The end-to-end conversion, step by step with commands, is in
[docs/PIPELINE.md](docs/PIPELINE.md).

## Repository map

```
README.md               this page (EN)          README.sr.md      Serbian
docs/                   documentation, reading order in docs/README.md
tools/                  95 stand-alone Python tools, one job each, --help on all
tests/                  unit tests (integration tests skip without local data)
ghidra_scripts/         generic headless Ghidra helpers used by tools/run_*_re.py
legacy/mmi3g-atlas/     the first Orion/ATLAS research pass (Aug 2026) and its log
scripts/                repository maintenance (tool index generator)
out/                    generated reports and builds, git-ignored
```

Every analysis tool is a script that walks the whole corpus, prints
progress, stops at the first inconsistency, writes a JSON report and a
`CHECKSUMS.sha256`. Claims in the docs point at those reports.

## Documentation

Start with [docs/README.md](docs/README.md). Short version:

1. [PROJECT_HISTORY.md](docs/PROJECT_HISTORY.md) — how this happened, day by day (EN)
2. [legacy/mmi3g-atlas/DOCS.md](legacy/mmi3g-atlas/DOCS.md) — 3G Plus firmware and the Orion format from zero (SR)
3. [ATLAS_CONTAINER.md](docs/ATLAS_CONTAINER.md) — proven `.ATLAS` container specification (SR)
4. [PKGDB_LAYERS.md](docs/PKGDB_LAYERS.md) — every layer of a 3G Plus map package (SR)
5. [PSF60_FORMAT.md](docs/PSF60_FORMAT.md) — the MIB map format (SR)
6. [PSF60_DECODER_GUIDE.md](docs/PSF60_DECODER_GUIDE.md) — tool-by-tool usage guide (SR)
7. [ORION_ADAPTER.md](docs/ORION_ADAPTER.md) — MIB source to Orion vocabulary (SR)
8. [PIPELINE.md](docs/PIPELINE.md) — the conversion, end to end (EN)
9. [FW_PROTECTION_MODEL.md](docs/FW_PROTECTION_MODEL.md) — signature, CRC, FSC (SR)
10. [IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) — closed and open items (SR)
11. [TOOLS.md](docs/TOOLS.md) — index of all tools (EN)

## Legal

Reverse engineering a file format for interoperability is permitted in the
EU (Directive 2009/24/EC, art. 6). The line this project keeps is
redistribution of map content and circumvention of the device's protection;
neither is done here. The code is MIT licensed, see [LICENSE](LICENSE).
Audi, MMI, MIB and HERE are trademarks of their owners; this project is not
affiliated with any of them.

## Background

The project started because one car had a map from 2023 and no way to get a
newer one. The story is in [docs/PROJECT_HISTORY.md](docs/PROJECT_HISTORY.md).
If you drive the same unit and want to continue from here, open an issue.
