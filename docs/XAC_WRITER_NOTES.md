# XAC / POI writer — working notes (in progress)

Goal: convert MIB POI/name source (`Landmark.psf`, `GlobalPOIIndices.psf`, and
Basic names) into the 3G Plus `XAC` layer, verified against the original.
Method (per project practice and owner's steering): read the MIB firmware
parser to reduce the source to a canonical form, read the 3G Plus firmware
reader to learn how the target is created, both through Ghidra — never guess.

## Done and verified

- **FLDB container** (`tools/fldb_container.py`): reads header + directory,
  round-trips the original **byte-identically** — XAC (2.14 GB, all 3 shards),
  and generalises to LIT and TMC. 5 unit tests. This is the wrapper writer.
- Directory entry layout (proven by round-trip): `name[24] + field(u32) +
  offset(u32) + size(u32)`, 36 bytes; header `header_size@0, file_count@0x0c,
  entry_size@0x10, "FLDB"@0x14`, directory at `header_size + 8`.
- Inner file types and their ASCII magics:
  `.ras`=`XACDB HEADER`, `.xah`=`ORTSNAMEN`, `.ort`=`GR POSTLEITZAHL`,
  `.plz`=`GLOBAL POIS`, `.poi`=`VERYSMART XAC HD`, `.b`/`.v`/`.xac`=`XAC HEADER`.

## The open question: the 4th directory field

Not a content checksum. Proven black-box:
- `.poi` (45 entries) share one field value across different sizes/content;
  `.plz`, `.ras`, `.xah` likewise constant.
- `.ort` (45), `.b` (45), `.v` (44), `.xac` (3752) have a **distinct field per
  entry**.
- No CRC-32 variant (zlib/bzip2/mpeg2/posix/jam/crc32c/raw) over payload, over
  any fixed prefix, or over the magic string reproduces it.

So it is a per-file **identifier**, constant for singleton types and unique for
the per-tile types (`.xac`/`.b`/`.v`/`.ort`) — not a checksum. Its exact
derivation must be read from the firmware, not forged or guessed.

## Firmware anchors (NavCore, SH4, base 0x08040000)

The reader is the C++ class **`CXacDb`** (symbols in NavCore strings):
`CXacDb::create(CHeapManagement&, IXacFileLoader&)`, `getGlobalOrt/Plz/Poi/Blk/
L1v`, `getLayerGroup`, `getFeAtGeoPos`, `<<IncompXACDB>>`. Filename patterns:
`%s_%.4s_%d%s.xac`, `%s_%.4s_1.xac`, `%s_%.4s_2.xac`.

Ghidra pass (`~/mmi3g-atlas/ghidra_scripts/dump_xac.java`, output
`~/mmi3g-atlas/xac_decomp.txt`): 344 XAC strings, **192 referencing functions**,
60 decompiled. `FUN_0810d200` references `<<IncompXACDB>>` and logs the DB
header with `%16s %16s %16s` (names) and `%ld %ld %ld %ld` (numeric fields) —
this is the DB-info / compatibility path and the place to read how the id/field
is validated.

## Next steps

1. From `xac_decomp.txt`, follow the `CXacDb::create` / `IXacFileLoader` path to
   the directory read and determine whether the 4th field is validated and how
   the per-tile id is derived (read-only; honest description of our content, no
   forging).
2. On the MIB side, decompile `libPathfinderApp.so` POI/landmark path to reduce
   `Landmark.psf` + `GlobalPOIIndices.psf` to a canonical POI record set.
3. Generate inner `.poi/.ort/.plz/.xac` from that canonical set, wrap with
   `fldb_container.py build`, verify structure against the original XAC.

## Scope reminder

This layer, like the rest, stops at producing correct converted content. No
device-side integrity value is forged and no signature is produced; that is the
owner's separate step.

## FLDB parser found in firmware (2026-09-04)

`FUN_080a7584` in NavCore is the FLDB open/validate function
(`~/mmi3g-atlas/fldb_parser.txt`; magic data at `0x083ccb54`):

- validates the `"FLDB"` magic: `memcmp(header + 0x14, "FLDB", 4)`, else returns
  `-0x6d`. Confirms the header layout used by `tools/fldb_container.py`.
- reads `header_size@0x00`, `file_count@0x0c`, `entry_size@0x10` and bounds-checks
  `file_count*entry_size + header_size` against the mapped size.
- loops up to 64 times doing 32-byte `memcmp` (matching the `getGlobal*` group /
  language names).

**Key result: the open/validate path performs NO checksum check on the 4th
directory field.** It is therefore not a load-time gate — it is an id / type
marker, not a checksum. Consequence for the writer:
- global types (`.poi/.plz/.ras/.xah`): copy the constant per-type value;
- per-tile types (`.xac/.ort/.b/.v`): the value is an id that must stay
  consistent with whatever references the tile (the spatial index that selects
  which `.xac` to load), not something that must satisfy a CRC.

Next: confirm what references the per-tile id (follow the `CXacDb::getLayerGroup`
/ index path), then it is safe to generate FLDB directories for our content.

## Decisive: the 4th field is informational (2026-09-04)

Two independent facts from the NavCore decompilation:

1. **Tiles are located by filename, not by the id field.** The loader builds
   the name with format strings (`%s_%.4s_2.xac`, `%s_%.4s_1.xac`,
   `%s_%.4s_%d%s.xac`) and the directory is matched by 24-byte name `memcmp`.
2. **No checksum gate** on the 4th field anywhere in the open/validate path
   (`FUN_080a7584`).

So the 4th directory field is neither validated nor used for lookup — it is
informational. **The FLDB container writer is therefore functionally complete:**
generate the directory with consistent values (copy the constant per-type value
for global types; a deterministic content-derived value for per-tile types) and
the firmware will load it. This closes the main unknown on the XAC container.

Remaining XAC/POI work is now purely the **inner content**: decode the MIB POI
source (`Landmark.psf`, `GlobalPOIIndices.psf`) via `libPathfinderApp.so`, and
emit `.poi/.ort/.plz/.xac` bodies in the Orion/XAC inner format, wrapped by
`fldb_container.py build`, verified against the original XAC bodies.

## Both ends mapped (2026-09-04) — remaining work is the inner-block encoder

XAC inner bodies are an Orion-family block: `char[16] type-magic` then a
big-endian header (`u32 size, u16 version, u16 count`) then an offset table,
then data. Observed magics and heads:
- `.ort` `GR POSTLEITZAHL ` + BE size, sparse 104-B place/postal stub
- `.plz` `GLOBAL POIS     `
- `.poi` / `.xah` `ORTSNAMEN       ` + BE `00014844` etc. + BE offset table
- `.xac` `_1` `XAC HEADER      ` = header: 4-char tile code (`AB03`), a
  reference to its `_2` data file (`EJ211_AB03_2`), and a build timestamp
- `.xac` `_2` = the data (VEKTORBLOCK vector records, already reverse
  engineered in `tools/orion_xac_vector_*`)
- `.ras` `XACDB HEADER    ` = DB-level header (db name, timestamp)

MIB POI source is already decoded: `tools/psf_decode.py landmarks` yields clean
records (display+search name with encoding, lon/lat, bbox, asset/category) from
`Landmark.psf`; `GlobalPOIIndices.psf` is the larger POI set.

So the pipeline is: MIB POI records (have) → spatial tiling → XAC inner blocks
(Orion-family header + VEKTORBLOCK bodies) → `fldb_container.py build`. The one
tool still to write is the **inner-block encoder**, proven the usual way: read
an original inner body, re-encode byte-identically, then feed MIB POI. The
container, the field question, and both data ends are done.

## Inner-block framing encoder done (2026-09-04)

`tools/xac_inner.py` reads the inner-block header + entry table and **rebuilds
it byte-identically**. Verified on real bodies extracted from the original XAC:
`.ort` (v3,count0), `.plz` (v9), `.xah` (v3), `.poi` (v3,count10 with a real
offset/size table), `.xac _1` (v9 ASCII header). `content_size == filesize-20`
confirmed for the table types. Unit tests in `tests/test_xac_inner.py`.

Layer stack now proven end to end for framing:
`fldb_container.py` (container) → `xac_inner.py` (inner block) → [innermost POI
record / VEKTORBLOCK bodies — reuse `orion_xac_vector_*`]. The one remaining
piece is generating those innermost record bodies from decoded MIB POI
(`psf_decode.py landmarks` output), then packing tiles into inner blocks.

## Innermost `.poi`/ORTSNAMEN content mapped (2026-09-04)

A `.poi` block (magic `ORTSNAMEN`, v3) holds `count` sub-blocks via the
(offset,size) table. In `EJ211_1.poi` (count=10):
- sub[0] = place-name table: fixed 8-byte ASCII name + BE u32 code, e.g.
  `HAABSAAR|0000091f? HAAPSALU|000009ff HAGUDI|00000a4b ...` (this XAC region
  EJ211 is Baltic — Estonian names), the code indexing into the other tables.
- the remaining sub-blocks are cross-reference tables: coordinate refs, phonetic
  forms, and a spatial index (u16/u8 keyed streams).

This is the deepest and most intricate encoder: a correct POI/ORTSNAMEN writer
must emit the name table plus its cross-referenced coordinate/phonetic/spatial
sub-tables consistently. The MIB source for it is `psf_decode.py landmarks`
(name display+search+encoding, lon/lat, bbox) plus `GlobalPOIIndices.psf`.

State of the XAC/POI layer: container ✓, inner-block framing ✓, field question ✓,
both data ends ✓. Remaining = this innermost content encoder (multi-table,
firmware-cross-checked), which is the deep core of the layer's writer.

## XAC block-type inventory + build-info gate (2026-09-04)

`xac_inner.py` round-trip now validated on **all 3977 inner files** of the
original XAC (100% byte-identical; versions v3=90 table types, v9=3797, v1=89,
v8=1). Framing is fully proven across the whole DB.

Firmware `FUN_0825ecc8` (references `ORTSNAMEN`, `VEKTORBLOCK`, ...) is the XAC
**build-info capability checker**. The XAC DB carries a `BUILD_INFO_TEXT` block,
and the reader checks dozens of feature flags before accepting it:
`checkFE_ZEN, checkZED, checkSTR, checkStrNames, checkMaxAnzGlobFEGruppen,
checkKlotoiden, check16BitVBlocknr, checkSpurinfos, checkCharacterSet
(ISO-8859-1 / UTF-8), checkVBIndexVersion, checkAttributeBitsZEN/ZFN,
checkMoreCountries, checkEcoCosts, ...`. Block types named:
`VEKTORBLOCK, ORTSNAMEN, PHONEME, ZF_NAMEN, ZE_NAMEN, ZED_NAMEN, STR_NAMEN,
XAC_HEADER, XACDB, OPEN_PROTECTION, MULTIIMPORT, BUILD_INFO_TEXT`.

Implication (honest): a from-scratch POI/name XAC that the firmware accepts must
emit these interdependent blocks (names, phoneme, coordinate/vector index) AND a
consistent BUILD_INFO_TEXT that passes the capability checks. That is a large,
multi-part encoder — the deep core of this layer, not a quick step.

### Pragmatic note for a working SD
POI/names are an enhancement; routing (PSD) is the substance and is done. Since
the loader locates XAC by filename and does not checksum-gate the directory, a
**working SD can keep the original XAC (Europe POI) unchanged and ship only the
updated PSD**. Building a new XAC from MIB POI is worth it for updated POI names,
but it is not required for a functional, newer-routing map.
