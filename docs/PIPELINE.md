# The conversion pipeline, end to end

From two archives you own (an MIB map release and the firmware that reads it,
plus one original 3G Plus map release and its firmware) to a 3G Plus routing
database `SRB.5_1.0.ATLAS` with its `.conf`. Every step is a stand-alone
tool; every step writes `report.json` and `CHECKSUMS.sha256` under `out/`.

The commands below are the ones that produced the full Serbia/Montenegro/
Kosovo build on 3 September 2026. Environment variables are listed in
[INPUT_INVENTORY.md](INPUT_INVENTORY.md).

```bash
export MIB_MAP_ROOT=.../Mib1/NavDB/SerbiaMontenegroKosovo_eu/0/default
export MMI3G_PKGDB=.../8R0051884KL_6.36.0_2023/pkgdb
export NAVCORE_ELF=.../extracted/mnt/ifs-root/usr/apps/NavCore
BASIC="$MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf"
PSD0="$MMI3G_PKGDB/PSD/APN221EU22093P1664a.5_1.0.ATLAS"
PSD3="$MMI3G_PKGDB/PSD3/APN221EU22093P1664a.5_1.2.ATLAS"
```

## 0. Why firmware first

Neither map format has public documentation. The parsers do: `NavCore` and
`MMI3GNavigation` (SH4, QNX IFS) on the 3G Plus side, `libPathfinderApp.so`
(ARM, QNX6) on the MIB side. Everything in `docs/` was read out of those
binaries in Ghidra and then confirmed by a script over a full dataset.

```bash
# 3G Plus firmware: QNX IFS with LZO1X
python3 legacy/mmi3g-atlas/ifs_tool.py unpack MU9411/ifs-root/61/default/ifs-root.ifs ifs-root.raw
python3 legacy/mmi3g-atlas/ifs_tool.py extract ifs-root.raw extracted
#   -> extracted/mnt/ifs-root/usr/apps/NavCore, MMI3GNavigation, usr/bin/vdev-logvolmgr

# MIB firmware: QNX6 image inside the SWDL dump
python3 tools/qnx6_extract.py ls "$MHI2_APP_IMG" /navigation
python3 tools/qnx6_extract.py extract "$MHI2_APP_IMG" /navigation -o "$MHI2_APP50/navigation"
#   -> libPathfinderApp.so (PNAV Core 10.2.5)
```

The `tools/run_*_re.py` runners regenerate the decompiled evidence quoted
in the docs from a headless Ghidra project. They are optional for the
conversion itself.

## 1. Read the MIB source

```bash
# What is in the file: wrapper, signature, metadata, cluster indexes
python3 tools/psf_decode.py inspect "$BASIC"
python3 tools/psf_decode.py export-source "$BASIC" --output out/serbia_basic_source --layout container

# Validated routing graph: nodes.jsonl + edges.jsonl in Orion vocabulary,
# with firmware-style Latin transliteration for Bosnian/Serbian/Montenegrin
python3 tools/basic_graph_export.py "$BASIC" \
  --output out/basic_graph_export_full --sample-limit 0 \
  --transliterate-identifier 30 --transliterate-identifier 33 --transliterate-identifier 48

# Clothoid centerlines (every polyline leg -> zero-curvature clothoid segment)
python3 tools/orion_clothoid_export.py "$BASIC" \
  --output out/orion_clothoid_source_full --sample-limit 0
```

Optional, not needed for the routing build but part of the source contract:
road attributes (`run_basic_road_attributes_stage.py`), names and languages
(`run_basic_name_stage.py`), AdvancedRouting/ADAS join
(`pre_writer_layers_export.py`). See
[PSF60_DECODER_GUIDE.md](PSF60_DECODER_GUIDE.md).

Result for Serbia: 717,730 nodes, 838,433 edges, 3,895,681 centerline points.

## 2. Verify the reference: the original 3G Plus PSD

Before writing anything, the writer's understanding of the container is
checked against the original database. One manifest runs all nine stages
with dependencies and gates:

```bash
python3 tools/run_container_pipeline.py tools/orion_container_pipeline.json \
  --state out/orion_container_pipeline_state.json --jobs 3
```

Stages: HEADER decode on four databases; block grammar (every byte explained);
INDEX tree and root; block round-trip (structure byte-identical, codec
semantically identical); spatial key probe; tile formula; tile grid;
assembler round-trip of the whole 3-part PSD. Expected: all green, 0
deviations, 254,828 blocks in place.

`tools/orion_psd_reference_profile.py` and `tools/orion_column_codec.py`
are the deeper reference for the column layer (42,066 schemas, all
byte-identical through split and assemble).

## 3. Build the 3G Plus database

```bash
# 3a. Partition the MIB graph into cells of the Orion binary tree.
#     Split by nodes; an edge belongs to the cell of its start node.
python3 tools/orion_cell_partition.py \
  out/basic_graph_export_full/nodes.jsonl out/basic_graph_export_full/edges.jsonl \
  --output out/orion_cell_partition_full

# 3b. One decoded graph chunk per cell -> LZMA1 raw -> CONTAINER block.
#     Cells whose chunk exceeds 64 KiB are reported as needs_split.
python3 tools/orion_cell_chunk_writer.py out/orion_cell_partition_full/cells.jsonl \
  --nodes out/basic_graph_export_full/nodes.jsonl \
  --edges out/basic_graph_export_full/edges.jsonl \
  --clothoids out/orion_clothoid_source_full/clothoid_edges.jsonl \
  --output out/orion_cell_chunks_full

# 3c. HEADER + REVISION + INDEX tree + blocks -> parts of the database.
#     The original part 0 supplies the HEADER fields that are copied, not derived.
python3 tools/orion_atlas_assemble.py \
  --blocks out/orion_cell_chunks_full/blocks.jsonl \
  --reference-part0 "$PSD0" \
  --base-name SRB \
  --output out/orion_atlas_build_full \
  --write out/orion_atlas_build_full/pkg

# 3d. The .conf next to it: size and MD5 as the package loader expects.
python3 tools/orion_conf_write.py write out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS \
  --template "$MMI3G_PKGDB/PSD3/PSD3.conf" \
  --output out/orion_atlas_build_full/pkg/PSD.conf
```

Result for Serbia: 3,877 cells, 3,915 blocks, `SRB.5_1.0.ATLAS` of
32,303,664 bytes, one part, two INDEX leaves, largest decoded chunk 65,440 B.

## 4. Verify the build with the same readers

```bash
python3 tools/orion_block_grammar_verify.py out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS --output out/orion_atlas_build_full/v_grammar
python3 tools/orion_index_decode.py         out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS --output out/orion_atlas_build_full/v_index
python3 tools/orion_block_writer.py         out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS --output out/orion_atlas_build_full/v_roundtrip
python3 tools/orion_tile_formula_verify.py  out/orion_atlas_build_full/v_roundtrip/graph_blocks.jsonl --output out/orion_atlas_build_full/v_formula
python3 tools/orion_layer_survey.py         out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS --limit 5
```

Expected: grammar 3,920/3,920 with coverage 1.0; index 0 failures; block
round-trip 3,915/3,915; key formula exact on 3,915/3,915; schemas readable.

## 5. Where the pipeline stops

The output of step 3 is a structurally complete, self-verified `.ATLAS`
database with a matching `.conf`. That is the end of what this repository
does.

Installing it on the car is a separate barrier that this project does not
cross. At install time the unit verifies a chain: the map package (`.pkg`)
carries a CRC of every `.conf` and is signed with the publisher's private
key (`.pkg.sig`), and the FSC licence is bound to the map part number. A new
map means a new MD5, a new `.conf` CRC and a package only the publisher can
sign. The chain is documented, read-only, in
[FW_PROTECTION_MODEL.md](FW_PROTECTION_MODEL.md). Nothing here produces,
forges or replaces that signature, and no CRC-collision or padding trick to
defeat the integrity check is part of this repository.

## What the generated database contains and what it does not

Contains: the routing graph (nodes, edges, From/To), clothoid centerlines,
PointLlh/PointLld coordinates, the property lists the original uses for
Adas/Urban/AudiUrban (Adas and AudiUrban conservatively zero), names as
logical name references.

Does not contain: VidTable blocks and the XAC name text they point to, speed
and lane property classes beyond the proven ones, AdvancedRouting and ADAS
semantics, and the other package layers (3D cities, terrain, text, TMC, POI)
whose formats are decoded in [PKGDB_LAYERS.md](PKGDB_LAYERS.md) but not yet
written. Status per item: [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md).
