# Project history

One car, an Audi A6 (C7) with MMI 3G Plus, firmware `HN+R_EU_AU_K0942_4`,
map database `8R0060884JN` (ECE 6.34.1). The last official release for that
unit is 6.36.x from 2023. This is how the project went from "what is on
that SD card" to a finished converter, in the order it actually happened.
Dates are 2026.

## 30–31 August: the 3G Plus side, from zero

- The firmware package (`MU9411`) is unpacked. The root image is a QNX IFS
  with LZO1X compression; no Mac tool handled it, so `ifs_tool.py` was
  written with its own pure-Python LZO1X decompressor. 345 files come out.
- The map parser is found: `usr/apps/NavCore`, a 7 MB ELF for Renesas SH4.
  Ghidra is installed and driven headless with Java scripts.
- From the code: the map is read as an ISO9660 volume in 2048-byte sectors,
  sector numbers are packed in 24 bits, so 2^24 × 2048 = 32 GiB is a
  structural ceiling. That explains the well-known 32 GB card limit.
- A map release (6.36.0) is obtained and its smallest `.ATLAS` file
  examined. Entropy says: structured, not encrypted. The header is decoded
  ("HEADER", "Orion", "Atlas", sizes of both parts of a split database).
- The file is a chain of blocks; each block carries its own size, a schema
  written as length-prefixed names and types, and a 16-byte terminator.
  The terrain layer decodes cleanly: a 65536 × 65536 grid of 16-bit
  heights at 3 arc-seconds, coordinates as int32 degrees × 10^7.
- Block payloads are LZMA1 raw (lc=3 lp=0 pb=2). The routing layer (PSD)
  unpacks and exposes its schema: Longitude, Latitude, PointLlh,
  CenterlineGeometry, Lane, ManoeuvrePart, AdasProperty, and so on.
- The column layout is columnar with bit-level packing. Three column codecs
  are read out of `CDecompression::create`; `calculateOffsets` shows the
  sequential layout and the per-column bit mask.
- First real coordinates. Tiles are power-of-two cells (2^18 units ≈
  0.026°) anchored at zero. A GeoJSON export shows road networks.

## 1 September: confirmation, integrity, and a source of fresh data

- The longitude column carries an offset. Measured by counting hits on land
  versus water and in known cities: 78.25°. Exported points over Kyiv draw
  the Dnipro embankment, the ring road and the Boryspil spur. The whole
  decoding chain is confirmed against a real map.
- The integrity chain is reproduced from `vdev-logvolmgr`: `.conf` carries
  the full-file MD5 and two quick-check MD5s (first 100 KiB, 100 KiB at the
  middle). The tool's own help text says MD5 is primary and CRC32 is "for
  testing only". The `.ATLAS` files themselves contain no internal checks.
- Repack test: 399 blocks unpacked and repacked; all decode correctly,
  none byte-identical (different LZMA SDK version), 46.7 % fit in the
  original size.
- A MIB map release (`P470_N60S5MIBH3_EU`, April 2026) and the MIB-side POI
  package are examined. They are not for 3G Plus, but the content is not
  encrypted: street names are plain UTF-8. The wrapper is diagnosed: no
  compression in the sampled region, bit-packed records, RSA-1024 delivery
  signature. Conclusion: the obstacle is the schema, not protection.
- The MIB2 firmware (`MHI2_ER_AU57x_K3663_1_MU1425`) is obtained. The
  navigation parser lives in a QNX6 image that macOS cannot mount.

## 1–2 September: the MIB side, a new project

A new project folder is started with a stricter rule: every analysis is a
script that walks the whole corpus, prints progress, stops at the first
inconsistency, writes a JSON report and checksums, and has tests.

- `qnx6_extract.py`: a read-only QNX6 reader, standard and old Audi MMI3G
  superblock layouts. `libPathfinderApp.so` (PNAV Core 10.2.5) is extracted.
- `psf_decode.py`: the PSF60 wrapper, metadata TLV, cluster indexes, and
  the two firmware codecs (LZMA-Alone and zlib). The earlier "no
  compression" conclusion is corrected: the sampled region was simply the
  uncompressed name table. The full Serbia Basic file yields 65,527 streams.
- Basic clusters: 3,336 clusters, 838,433 edge descriptors, 717,730 node
  records, all cross-references valid in both directions.
- Geometry grammar and coordinate decoder: 903,487 sub-records, 3,960,735
  points, none outside its cluster bbox.
- Handle-2 records and text: 182,377 semantic records, 271,823 primary and
  262,187 phonetic strings decoded without error. Language IDs are read
  from the world-country records (30 Bosnian, 31 Albanian, 33 Serbian,
  48 Montenegrin) and cross-checked against the Albania and Bosnia maps.
- Road attributes: static direction, speed limits, lanes, passing
  restrictions, automotive masks, and the dynamic directory with
  time-condition evaluation, all traced to consumer addresses in the parser.
- AdvancedRouting and ADAS: lossless framing over the full corpus, one
  record per edge. Internal semantics left open and not invented.
- Clothoid adapter: every polyline leg becomes a zero-curvature clothoid
  segment; endpoint error 0.0.
- On the 3G Plus side, the original PSD3 is profiled as the writer's
  reference: 42,066 schemas, 649,210 column codec bytes, all byte-identical
  through split and assemble. The first Orion objects (PointLlh, Node/Edge,
  centerlines, properties) are written and self-validated.

## 3 September: the container, the writer, the limit

- The INDEX tree is found in part 0 of the database (REVISION → root → 125
  leaves of 2048 entries → blocks). One rule on every level: the separator
  is a copy of the header of the next child's first block.
- Correction: the 835 "corrupt" LZMA blocks were never corrupt. The
  dictionary is 1 MiB, not 64 KiB.
- The block key is decoded: a Z-order interleave of the cell origin in a
  global binary tree with alternating axes, level `A`, offsets 0x44000 and
  0x2000 in key space. Exact on 100 % of graph blocks in all parts.
- `orion_atlas_assemble.py` rebuilds the original 3-part, 5.04 GB PSD from
  its own blocks with zero deviations. The writer is proven.
- The full Serbia dataset goes through the chain: graph → clothoids →
  3,877 cells → 3,915 CONTAINER blocks → `SRB.5_1.0.ATLAS` (32.3 MB) and its
  `.conf`. Every verifier passes.
- The protection model is read out of `MMI3GNavigation`: `CPNavDBChecker`
  state machine, signature verified by `cryptomanager`, CRC, FSC bound to
  the part number, factory skip switches and who sets them. Documented as
  is; nothing bypassed.
- The remaining pkgdb layers (3D cities, terrain, text, TMC, POI) are
  surveyed and their container and schema formats decoded.

## 4 September: going public

A LinkedIn post announces the project. This repository is prepared: personal
paths replaced by environment variables, the first research pass moved to
`legacy/`, tool index generated, and everything that is map or firmware
content excluded.

## What was learned that was not known before

- Why the 32 GB limit exists (24-bit sector field), read from the code.
- That `.ATLAS` files are neither encrypted nor internally checksummed.
- The complete Orion container grammar, INDEX tree and spatial block key,
  proven by a byte-identical rebuild of a 5 GB database.
- The PSF60 wrapper, codecs, Basic cluster grammar, geometry, text and
  attribute encodings, proven over a full national dataset.
- Exactly where the device's acceptance chain sits and what it needs.
