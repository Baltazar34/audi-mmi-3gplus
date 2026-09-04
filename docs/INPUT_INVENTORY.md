# Lokalni inventar — Audi MMI/MIB projekat

## Promenljive okruženja

Alati, testovi i JSON manifesti ne sadrže lične putanje. Ulazi se zadaju
promenljivima okruženja (orkestratori rade `os.path.expandvars` nad
komandama, testovi ih čitaju sa podrazumevanom `/private/tmp/...` vrednošću):

| Promenljiva | Šta pokazuje | Primer |
|---|---|---|
| `MIB_ARCHIVE` | MIB arhiva mapa | `.../P470_N60S5MIBH3_EU.7z` |
| `MIB_EXTRACT` | folder u koji je arhiva raspakovana | `/private/tmp/mib` |
| `MIB_MAP_ROOT` | folder jedne regije unutar raspakovane mape | `$MIB_EXTRACT/Mib1/NavDB/SerbiaMontenegroKosovo_eu/0/default` |
| `MHI2_ARCHIVE` | MIB2 (MHI2) firmware arhiva | `.../MHI2_ER_AU57x_K3663_1_MU1425_AIO.7z` |
| `MHI2_EXTRACT` | folder u koji je firmware raspakovan | `/private/tmp/mhi2_k3663` |
| `MHI2_APP_IMG` | QNX6 image sa navigacijom | `$MHI2_EXTRACT/K3663_1/1/MMX2/app/50/default/app.img` |
| `MHI2_APP50` | folder izvučen iz `app.img` (`qnx6_extract.py`) | `/private/tmp/mhi2_app50_extracted` |
| `MMI3G_MAP` | raspakovano originalno 3G Plus izdanje mapa | `.../8R0051884KL_6.36.0_2023` |
| `MMI3G_PKGDB` | njegov `pkgdb` folder | `$MMI3G_MAP/pkgdb` |
| `NAVCORE_ELF` | NavCore iz 3G Plus firmvera (`legacy/mmi3g-atlas/ifs_tool.py`) | `.../extracted/mnt/ifs-root/usr/apps/NavCore` |
| `MMI3G_NAV_ELF` | MMI3GNavigation iz istog firmvera | `.../extracted/mnt/ifs-root/usr/apps/MMI3GNavigation` |
| `NAVCORE_GHIDRA_PROJECT` | Ghidra projekat sa NavCore-om | `~/mmi3g-atlas/ghidra_proj` |

Ostatak dokumenta je inventar kakav je napravljen 2026-09-01, sa putanjama
zamenjenim ovim promenljivima.

Inventar je napravljen 2026-09-01. Ulazni arhivi se čitaju read-only; projekat
ne izvršava M.I.B. skripte i ne radi bilo kakav flash/upis na MMI uređaj.

## Primarni ulazi

### MHI2 firmware

- Fajl: `$MHI2_ARCHIVE`
- Veličina: `6.177.024.561 B` (približno 5,8 GiB)
- SHA-256: `393619c139e606efde32ad46d5c1ad997b76d18218ec82ed96128be07cfef975`
- Radna ekstrakcija: `$MHI2_EXTRACT`
- Ekstrahovani MMX2 app50: `$MHI2_APP50`
- Navigacioni parser:
  `$MHI2_APP50/navigation/libPathfinderApp.so`
- Parser SHA-256:
  `636b7d1440938928d97435efc3897cf5baed0b1f768ad03f7efd0b6b109c4ee9`

`/private/tmp` putanje su radni cache i mogu nestati posle restarta. Originalni
firmware arhiv u Downloads je trajni izvor.

### MIB mapa

- Fajl: `$MIB_ARCHIVE`
- Veličina: `15.343.840.520 B` (približno 14,3 GiB)
- SHA-256: `4a390301e165a011c3b038c5f17ec42786d6caeb7edb3d176abeed6b6fbb8fd6`
- Radna ekstrakcija: `$MIB_EXTRACT`
- Serbia test dataset:
  `$MIB_MAP_ROOT`
- Format iz `mapprefs.xml`: `PSF2DDTM` (`MapFormat=4`)
- Verzija iz `PSFVersion.txt`: `60DREID4ADAS7`

### Originalni 3G Plus reference input (read-only)

- NavCore firmware binary:
  `$NAVCORE_ELF`
- 3G Plus map package root:
  `$MMI3G_PKGDB/`
- XAC shardovi korišćeni za bridge:
  `XAC/kN221EUx01_0.db`, `XAC2/kN221EUx01_1.db` i
  `XAC3/kN221EUx01_2.db`.

Ovi ulazi se čitaju isključivo za format/reference analizu. Firmware NavCore
drži XAC descriptor i name-resolver kod; XAC shardovi drže fizičke vector
recorde i još-neidentifikovani `xac_name` data sloj. Nema upisa, repack-a ili
flash akcije nad njima.

## M.I.B. alat, dokumentacija i offload/backup skripte

Kanonska kopija:

`M.I.B._More-Incredible-Bash-3.7.1.zip`

SHA-256:

`1eb44a42c028eb43f27453b16c51507f26b1427ed2b5f2760a70addba534fb62`

Paket sadrži, između ostalog:

- `README.md`, `PATCH COMPATIBILITY TABLE.pdf` i MHI2 password-list PDF;
- `apps/backup` i `apps/backupplus`;
- `esd/scripts/backupplus_app.sh`, `backupplus_nav.sh`,
  `backupplus_rcc.sh`, `backupplus_system.sh` i ostale offload skripte;
- QNX pomoćne binarije i launcher/patch skripte.

Ovaj paket je operativni MMI toolkit, ne izvorni kod PSF60 map parsera.
Koristi se samo kao referenca; map format rekonstruišemo iz firmware
`libPathfinderApp.so` i validiramo prema stvarnim PSF fajlovima.

## Prethodni Claude/MMI3G rad

- Projekat: `legacy/mmi3g-atlas`
- Glavna dokumentacija: `legacy/mmi3g-atlas/DOCS.md`
- Python alati: `atlas_blocks.py`, `atlas_bits.py`, `atlas_recon.py`,
  `atlas_export.py`, `nds_names.py`, `ifs_tool.py`
- Ghidra skripte: `legacy/mmi3g-atlas/ghidra_scripts`

To je stariji MMI3G/Orion/ATLAS tok. Njegove tehnike i dokumentacija su
sačuvane kao istorijska referenca, ali zaključci se ne prenose automatski na
MHI2 PSF60. Konkretno, stara tvrdnja da PSF nema kompresiju nije tačna za
isporučene MIB1/MIB2 mape.

## Novi projekat i generisani izlazi

- Projekat: `<repo>`
- PSF60 dekoder: `tools/psf_decode.py`
- QNX6 ekstraktor: `tools/qnx6_extract.py`
- Basic semantički validator/source probe: `tools/basic_semantic_probe.py`
- Basic nested geometry validator: `tools/basic_geometry_grammar.py`
- Basic normalized geometry decoder: `tools/basic_geometry_decode.py`
- Basic handle-2 directory/header validator: `tools/basic_handle2_directory.py`
- Basic handle-2 SDString decoder: `tools/basic_handle2_text_decode.py`
- Basic world-country/language validator: `tools/basic_world_country_languages.py`
- Basic language/script/name profiler: `tools/basic_handle2_name_profile.py`
- Firmware-style name grouping/selection: `tools/basic_name_semantics.py`
- Kompletan autonomni name-stage runner: `tools/run_basic_name_stage.py`
- Automatski Albania/Bosnia archive cross-check:
  `tools/run_basic_identifier_crosscheck.py`
- Ponovljivi Ghidra handle-2 batch: `tools/run_basic_handle2_re.py`
- Basic validated graph/Orion-source exporter: `tools/basic_graph_export.py`
- Ponovljivi Ghidra geometry batch: `tools/run_basic_geometry_re.py` i
  `ghidra_scripts/`
- Format dokumentacija: `docs/PSF60_FORMAT.md`
- Basic storage/source layer za potvrđeni strict scan scope:
  `out/serbia_basic_source/`
- Landmark GeoJSON: `out/serbia_landmarks.geojson`
- Validirani Basic topology/geometry izveštaj i edge source uzorak:
  `out/basic_semantic_probe/`
- Validirani nested geometry grammar: `out/basic_geometry_grammar/`
- Validirani normalizovani edge geometry: `out/basic_geometry_decode/`
- Validirani handle-2 directory/header: `out/basic_handle2_directory/`
- Validirani handle-2 direktni tekstovi: `out/basic_handle2_text_decode/`
- Validirani world-country jezički ID-jevi: `out/basic_world_country_languages/`
- Validirani name ID/script/parovi: `out/basic_handle2_name_profile/`
- Cross-check Albania/Bosnia: `out/basic_identifier_crosscheck/`
- Validirani routing graph/Orion source: `out/basic_graph_export/`
- Latin/transliteration graph profil: `out/basic_graph_export_latin/`
- Autonomni zbirni name-stage: `out/basic_name_stage_latin/`
- Firmware RE batch artefakti: `out/firmware_re/basic_geometry/` i
  `out/firmware_re/basic_handle2/`
