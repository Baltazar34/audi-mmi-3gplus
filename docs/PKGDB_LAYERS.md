# pkgdb slojevi — format svakog dela baze

Poslednje ažuriranje: 2026-09-03. ATLAS (PSD) nije cela nav baza; ovde je
dokumentovan format **svih** slojeva `pkgdb`-a. Alat:
`tools/orion_layer_survey.py` + postojeći container/schema/FLDB parseri.

Dva porodična formata:

- **Orion `.ATLAS`** — isti container koji smo potpuno rešili (HEADER/CONTAINER/
  INDEX, codec 1/2/3, code-1 kolone). Koriste ga PSD, CTY, CTYS3TC, TER.
- **FLDB `.db`** — File Library DataBase: wrapper sa direktorijumom ugnežđenih
  fajlova. Koriste ga LIT, TMC, XAC. Magic `FLDB` na +0x14, imena od +0x228.

## 1. PSD — rutiranje  (REŠENO + writer)

Orion `.ATLAS`, codec 3 (LZMA1). Graf: `NodeRoadElement`, `EdgeRoadElement`,
`From/To`, `CenterlineGeometry`, clothoid, Property (Speed/Lane/Urban/Adas).
Kompletno dekodirano i **generisano iz MIB-a** (`SRB.5_1.0.ATLAS`). Vidi
`docs/ATLAS_CONTAINER.md`, `docs/ORION_ADAPTER.md`.

## 2. CTY / CTYS3TC — 3D gradovi  (šema rešena)

Orion `.ATLAS` (CTY codec 1, CTYS3TC codec 2/zlib). 213.042 chunka.
Legacy schema varijanta bez annotations. Dekodirana šema je kompletan 3D
scene format:

- geometrija: `AbsolutePoint` (Longitude/Latitude/Height), `RelativePoint`,
  `VertexArray`, `Primitive`, `Geometry`, `UniqueGeometry`;
- izgled: `TexturePoint`, `Normal`, `Color`, `Material`, `Binding`,
  `ImagePointer` (ContainerHandle/ImageIndex — teksture);
- organizacija: `MapContent`, `MapLayer` (Min/MaxScale), `MapDescription`
  (Bounding), `BoundingRectangle`, `Item`, `Atom`.

Prvi chunk je map-description (sadržaj/slojevi/opseg); 3D geometrija je u
narednim chunkovima. Kolone se čitaju istim code-1 čitačem kao PSD.

## 3. TER — teren  (šema rešena)

Orion `.ATLAS`, codec 1. Jedan composite: **`SoarTerrain`** sa članovima
`Heights`, `Errors`, `Radia`. To je SOAR (Stateless One-pass Adaptive
Refinement) terrain LOD mesh: visinska mreža + error metrika za nivo detalja
+ radijusi omeđujućih sfera. Kolone `0x34`/`0x24` nose nizove; čita se code-1.

## 4. LIT / LIT3GP — tekst/labele  (FLDB wrapper rešen)

FLDB `.db` → jedan ugnežđen `.LIT` fajl (`EJ211Ga.LIT`). `.LIT` je legacy
„lit" engine v3.8.7 (2009), zlib-kompresovan text/label DB — poznat iz starijeg
`mmi3g-atlas` toka. FLDB direktorijum (ime + offset/size) je dekodiran; unutrašnji
`.LIT` zapis je zaseban legacy podsistem.

## 5. TMC — saobraćaj  (FLDB wrapper rešen)

FLDB `.db` → 15 `.tlt` fajlova (`EJ211_MM_DD.tlt`, po datumima). To su TMC
location tabele (RDS-TMC standard: liste lokacijskih kodova za saobraćajne
poruke). FLDB direktorijum dekodiran; `.tlt` prati javni RDS-TMC location
table format.

## 6. XAC — POI / imena  (FLDB + vector/name most REŠEN)

FLDB `.db` → 439 fajlova: `.ras`, `.xah`, `.ort`, `.plz` (poštanski),
`.poi`, `.b`, sa `!dbinfo` blokom (`XACDB=EJ211, DB=1/3`). Ovaj sloj je
detaljno RE-ovan u glavnom toku: FLDB direktorijum, `VEKTORBLOCK` markeri,
vector record gramatika (`(b0&0xc0)==0xc0`, 11-bitni key), packed 14-bitne
name reference, i most `AtlasId → XacVectorOffset → record`. Vidi
`docs/CLAUDE_HANDOFF.md` (XAC checkpoint) i `out/orion_xac_*`.

## Sažetak stanja

| Sloj | Format | Stanje |
|---|---|---|
| PSD | Orion .ATLAS | rešen + generiše se iz MIB-a |
| CTY/CTYS3TC | Orion .ATLAS (3D scene) | šema/container rešeni |
| TER | Orion .ATLAS (SoarTerrain) | šema/container rešeni |
| LIT | FLDB → .LIT (zlib legacy) | wrapper rešen; inner legacy |
| TMC | FLDB → .tlt (RDS-TMC) | wrapper rešen; inner standard |
| XAC | FLDB → .ras/.xah/.poi | most i gramatika rešeni |

„Rešen" ovde znači: container, direktorijum i logička šema su dekodirani i
sadržaj je čitljiv istim dokazanim alatima. Puni semantički writer za svaki
sloj (kao za PSD) je zaseban obiman posao po sloju; format je identifikovan,
dekodiranje dokazano. Prihvatanje na uredjaju zahteva izdavacev potpis paketa.

## FLDB container writer — 2026-09-04

`tools/fldb_container.py` je zajednički čitač/round-trip/writer za sve tri
FLDB-porodice (XAC, LIT, TMC). Dokazano **bajt-identičnim round-trip-om** na
originalu (memorijski bezbedno, mmap):

| Fajl | Stavki | byte_identical | unowned |
|---|---|---|---|
| XAC `kN221EUx01_0.db` (2,14 GB) | 3978 | da | 9,11 % |
| XAC2 | 3384 | da | 0,28 % |
| XAC3 | 418 | da | 1,01 % |
| LIT | 1 | da | 100 % (sav sadržaj je jedan ugnežđen `.LIT`) |
| TMC | 15 | da | 7,0 % |

Directory (ime[24] + crc32 + offset + size, 36 B) se regeneriše bajt-identično.
Otvoreno pre pisanja NOVOG sadržaja (nije forging — pošten opis našeg sadržaja):
1. **FLDB direktorijumsko 4. polje NIJE checksum sadržaja.** Dokazano: dve `.poi`
   različite veličine/sadržaja imaju isti tag, dva `.ort` iste veličine različit;
   nijedna CRC-32 varijanta (zlib/bzip2/mpeg2/posix/jam/crc32c/raw) ni nad
   sadržajem ni nad prefiksom se ne poklapa. Konstantno je po `.poi`/`.plz`,
   varira po `.ort`. Semantika se čita **iz firmvera (FLDB reader u Ghidri)**,
   ne pogađa se — to je sledeći korak pre XAC writer-a.
2. **„Unowned" regioni** (9 % XAC-a = VEKTORBLOCK/continuation zona koju direktorijum
   ne opisuje) — writer mora da ih reprodukuje iz MIB POI izvora.
3. Generisanje unutrašnjih `.poi/.xac/.ras` iz MIB `Landmark`+`GlobalPOIIndices`.
