# PSF60 format — potvrđeni nalazi iz MHI2 parsera

Ovaj dokument odvaja potvrđene strukture od radnih hipoteza. Izvor istine je
Audi MHI2 `libPathfinderApp.so` iz MU1425 firmware-a, ukršten sa lokalnim
`P470_N60S5MIBH3_EU` mapama. Sve operacije su read-only.

## Parser i format

- Aktivni `mapprefs.xml` format je `PSF2DDTM` (`MapFormat = 4`).
- `PSFVersion.txt` je `60DREID4ADAS7`.
- `libPathfinderApp.so` je 32-bitni ARM/QNX ELF, PNAV Core 10.2.5.
- Debug sidecar naveden u `.gnu_debuglink`,
  `libPathfinderApp.so-20160718160238.sym`, nije prisutan u firmware-u.
- Lokalni Ghidra projekat koristi image-base slide `+0x10000`; za raw
  ELF/llvm-objdump adresu od Ghidra VA treba oduzeti `0x10000`.
- Firmware je AIO izdanje sa RCC izmenama za FEC/CP. Navigacioni MMX2 parser
  je ipak pogodan za statičku rekonstrukciju formata.

Raniji zaključak u starom `mmi3g-atlas/DOCS.md` da PSF nema kompresiju bio je
pogrešan. PSF sadrži desetine hiljada validnih LZMA-Alone tokova. Promašeni su
jer PSF enkoder često stavlja malu, proizvoljnu veličinu rečnika jednaku
raspakovanoj veličini, umesto tipičnog power-of-two rečnika.

## Fiksno zaglavlje i rep

Potvrđena little-endian polja:

| Offset | Tip | Značenje |
|---:|---|---|
| `0x00` | `u16` | slot kind: 0 regular, 1 DTM |
| `0x02` | `u32` | PSF verzija, ovde 60 |
| `0x06` | `u32` | granica zaglavlja pokrivena potpisom / početak prvog payload-a, ovde `0xF2` |
| `0x0A` | `u32,u32` | primary/world blok offset i veličina |
| `0x35` | `u32,u32` | combined tail offset i veličina |
| `0x4D` | `u32` | ukupna veličina fajla; parser je poredi sa storage veličinom |
| `0x51` | `u32` | Unix vreme |
| `0x55` | `u32` | customer ID; proverava se u `ReadRegularSlot` |
| `0x5F` | `u32,u32` | opcioni junction-view blok |
| `0x7A` | `u32,u32` | metadata/footer TLV blok |
| `0x96` | `u32,u32` | spatial/world indeks blok |

Kod regularnog Basic slota proverava se kontigvitet:

```text
spatial_index -> world -> metadata -> combined_tail -> EOF
```

`content.pkg` checksum pokazuje na prvih 128 bajtova `combined_tail` bloka i
poklapa se bajt-po-bajt. Lokalni fajlovi završavaju sa 128 B verifikacionog
bloba, 128 nula i markerom `80 00 06 01 00 00`, ukupno 262 B.

`hashes.txt` je SHA-1 po uzastopnim delovima od 512 KiB:
`CheckSum` je chunk 0, `CheckSum1` chunk 1 itd. Svi lokalni fajlovi prolaze
proveru.

## Metadata TLV

Metadata zapis je:

```text
u24le field_id
u8    type
...   vrednost
```

Potvrđeni tipovi iz firmware funkcije na ELF adresi `0x2925f0`:

| Kod | Vrednost |
|---:|---|
| 1/2 | `i8` / `u8` |
| 3/4 | `i16` / `u16` |
| 5/6 | `i32` / `u32` |
| 7 | NUL-terminiran UTF-8 string |
| 8/9 | `u16 count` + niz `i8` / `u8` |
| 10/11 | `u16 count` + niz `i16` / `u16` |
| 12/13 | `u16 count` + niz `i32` / `u32` |
| 14 | `u16 count` + NUL-terminirani UTF-8 stringovi |

`Basic.psf` metadata blok ima 2.673 B i tačno 283 zapisa. Field `0x8a = 4`
i field `0x8b = 32` određuju početak i stride spatial/world zapisa. Field
`0x13f`, tip 13, ima `[622510, 1, 4372]`: offset indeksa, tree depth i
veličinu indeksa. Blok je `u32 count=364` plus 364 zapisa po 12 B.

## PSFHandle i kompresija

Rekonstruisan 21-bajtni `PSFHandle`:

| Offset | Polje |
|---:|---|
| `+0x00` | `u32 slot_id` |
| `+0x04` | `u32 file_offset` |
| `+0x08` | `u32 stored_size` |
| `+0x0C` | `u8 compressed` |
| `+0x0D` | `u8 encrypted` |
| `+0x0E` | 2 B padding |
| `+0x10` | `u32 cluster_id` |
| `+0x14` | dodatni tag, semantika još nepoznata |

Dispatcher na ELF `0x261fbc` bira codec po slotu:

- `1`: LZMA-Alone. Header je 5 B properties/dictionary + 8 B izlazna
  veličina; payload počinje na `+13`.
- `2`: zlib. Prva 4 B su LE izlazna veličina, zlib stream počinje na `+4`.

Lokalni PSF fajlovi koriste LZMA properties `0x5d`; dictionary i `u64`
uncompressed size su jednaki. Nije pronađen validan zlib blok u ovim
uzorcima.

## Potvrđeni indeksi

### Landmark

Na `0xFA` je `u32 count`, zatim `count * 24`:

```text
u32 bbox_0
u32 bbox_1
u32 bbox_2
u32 bbox_3
u32 compressed_offset
u16 compressed_size
u16 cluster_id
```

Serbia fajl ima 72 zapisa. Svih 72 deskriptora tačno pokrivaju 72 susedna
LZMA bloka od `0x7BE` do footer-a `0x3411`.

Raspakovani payload počinje Web Mercator bbox-om. Cluster header na `0x16`
sadrži broj Landmark zapisa. Svaki zapis ima poziciju relativnu na bbox,
putanju asset-a i jednu ili više varijanti imena. Serbia uzorak daje 78
objekata; lokalizovani naziv je UTF-8, dok search/transliteracija kod nekih
albanskih zapisa koristi Latin-1.

### ADAS

Pet grupa; svaka je `u32 count` pa `count * 12`:

```text
u32 cluster_id
u32 compressed_offset
u32 compressed_size
```

Brojevi grupa su `682, 682, 682, 682, 608`, ukupno 3.336. Posle grupa je
40-bajtni pomoćni blok, zatim potpuno kontigvan LZMA lanac
`0x9D8E..0x1BE3A09`.

Svaki raspakovani ADAS klaster ima potvrđen lossless framing:

```text
u8  edge_count
u16le record_data_offset
u32le decoded_cluster_size
u8  encoded_record_sizes[]
u8  records[]
```

`decoded_cluster_size` mora biti jednak dužini payload-a. Veličina recorda
manja od `0x80` zauzima jedan bajt; postavljen high bit daje dvobajtni oblik
`((first & 0x7f) << 8) | second`. Tabela mora imati tačno `edge_count`
vrednosti i njihov zbir mora pokriti ostatak klastera. Serbia korpus ima 3.336
klastera, 838.433 recorda i 49.651 dvobajtno kodiranu veličinu. Cluster ID i
redni broj recorda odgovaraju Basic edge-u 1:1.

Ovo zatvara fizičko/record-level dekodiranje. Unutrašnji sadržaj ostaje
sačuvan kao `raw_hex`; firmware `FUN_009e6d10`, `FUN_009df8fc` i
`FUN_009e0ea0` potvrđuje spajanje ADAS recorda sa Base/Complete edge
containerima i emitovanje scalar/profile attribute-a. Javna imena svih
internih ADAS attribute ID-jeva još nisu dokazana.

### AdvancedRouting

Grupa je `u32 count` pa `count * 20`:

```text
u32 cluster_id
u8  extra[8]
u32 compressed_offset
u32 compressed_size
```

Brojevi grupa su osam puta 409, zatim 63 i završnih 7, ukupno 3.342. Između
grupe 63 i završne grupe je 72-bajtni pomoćni blok. LZMA lanac je
`0x1067A..0x364BF5`.

Raspakovani klaster koristi potvrđeni direktorijum:

```text
u8    record_count
u16le cluster_metadata
u16le record_offsets[record_count]
u8    records[]
```

Prvi offset mora biti `3 + 2*record_count`, offseti su strogo rastući, a
poslednji record završava na kraju payload-a. Svih 3.342 streamova prolazi
ovo pravilo: ukupno 839.501 record. Od toga se 838.313 recorda veže za Basic
edge, 120 Basic edge-a nema odgovarajući record, a sedam posebnih cluster
ID-jeva `12608912..12608918` sadrži još 1.188 recorda. Najčešći record je 5 B
(833.624 slučaja), ali decoder ne pretpostavlja fiksnu veličinu.

Firmware potvrđuje da sloj učestvuje u uparenom Routing/Guidance load-u. Samo
framing i edge/supra pripadnost su zatvoreni; `raw_hex` se ne naziva manevrom
ili zabranom dok consumer tag mapa ne bude nezavisno dokazana.

### Basic spatial/world indeks

Header polja `0x96/0x9A` vode na `u32 count` i zapise po 32 B:

```text
s32 bbox[4]
u32 cluster_id
u32 compressed_offset
u32 compressed_size
u32 flags
```

Serbia uzorak ima osam zapisa. Svi targeti su validni, susedni LZMA blokovi.
Bit 0 flags polja utiče na status; ne treba ga automatski zvati compression
flag.

### Basic glavni spatial indeks sa dva handle-a

Metadata field `0x139` sadrži osam trojki
`[root_offset, tree_depth, last_leaf_offset]`. Šest je aktivno. Depth-2 root
je `u32 count` pa `count * { s32 bbox[4], u32 child_offset }`.

Leaf stranica je:

```text
u32 link_a
u32 link_b
u32 count
count * {
  s32 bbox[4]
  u24 cluster_id
  u8  flags                 # bit 0/1: compressed handle A/B; bit 3: record flag
  u32 handle_a_offset
  u16 handle_a_size
  u32 handle_b_offset
  u16 handle_b_size
}
```

Sedamnaest leaf stranica imaju ukupno 3.336 zapisa i 6.672 validna LZMA
handle-a. Internal root-ovi su na `0x436E` (2 deteta) i `0x1A2BE`
(11 deteta). Metadata `0x96=12` i `0x97=32` potvrđuju leaf base i stride.

### Basic ID indeks sa tri handle-a

Metadata field `0x138 = [0x3933A, 2, 0]` vodi na internal root:

```text
u32 separator_count
separator_count * { u32 child_offset, u32 separator_cluster_id }
u32 final_child_offset
```

Šesnaest leaf stranica (15 puta 215 zapisa, poslednja 111) koriste 38-bajtni
zapis:

```text
u24 cluster_id
u8  flags                   # bit 0/1/2: compressed handle 0/1/2
3 * { u32 compressed_offset, u16 compressed_size }
s32 bbox[4]
```

Ukupno je 3.336 zapisa i 10.008 handle-a. Svih 6.672 handle-a iz prethodnog
dual-spatial indeksa nalazi se i u ovom indeksu; treći handle dodaje još 3.336
payload-a. Metadata `0x94=4` i `0x95=38` potvrđuju leaf base i stride.

#### Semantički sadržaj handle-a 0 i 1

Firmware accessor-i oko Ghidra VA `0x0154f730..0x01550354` i globalna
validacija svih 3.336 zapisa potvrđuju sledeću unutrašnju podelu. Handle 0
sadrži topology klaster:

```text
u16 edge_descriptor_base     # bit 15: kompaktni node offseti; low15: baza
u8  edge_count               # offset +2
u8  opaque_03
u8  node_count               # offset +4
u8  opaque_05_14[10]

# node offset tabela počinje na +15
# kompaktno: jedan u16 apsolutni offset na četiri node-a,
#            zatim po tri u8 delta-offseta u fiksnom drugom delu tabele

# na edge_descriptor_base sledi edge_count zapisa po 9 B
edge_descriptor {
  u8 opaque_00_03[4]
  u8 endpoint_flags          # bit 6 za endpoint A, bit 7 za endpoint B
  u8 endpoint_a_ref          # lokalni indeks ili indeks u external u32 stolu
  u8 endpoint_b_ref
  u8 opaque_07_08[2]
}

# external node-ID sto počinje na sledećoj parnoj adresi posle deskriptora
# node zapisi počinju na offsetima iz prve tabele
node_record {
  u4 local_edge_count        # high nibble prvog bajta
  u4 external_edge_count     # low nibble
  u8 opaque_01
  u8 local_edge_ids[local_edge_count]
  u32 external_edge_ids[external_edge_count]
  u8 trailing_attributes[]   # granica je sledeći node offset
}
```

Lokalni edge/node ID je `cluster_id << 8 | local_index`. Eksterni edge ID
se pri lookup-u normalizuje maskom `0xe7ffffff`; endpoint A/B nazivi čuvaju
redosled firmware slotova i još ne tvrde smer putovanja.

Handle 1 daje geometry zapis za svaki fiksni edge deskriptor:

```text
s32 bbox_min_x
s32 bbox_min_y
s32 bbox_max_x
s32 bbox_max_y
u16 coordinate_table_offset  # offset +16
u8  opaque_18_19[2]
u8  geometry_flags           # +20; bit 0=u32 komponente, bit 1=kompaktni offseti
u8  coordinate_scale         # +21
u8  coordinate_table_count   # +22
u8  edge_count               # offset +23

# offset tabela počinje na +24
# direktno: edge_count * u16
# kompaktno: jedan u16 na osam edge-a + sedam u8 delta-offseta

# na coordinate_table_offset sledi coordinate_table_count zapisa
coordinate_entry {
  u8 marker
  u16/u32 encoded_x          # širinu bira geometry_flags.bit0
  u16/u32 encoded_y
}

u8 geometry_records[]        # tačne granice dolaze iz offset tabele
```

Svaki geometry zapis zatim počinje dvobajtnim header-om i nizom subrecord-a:

```text
u8 geometry_record_flags
u8 subrecord_count

subrecord {
  u8 flags                   # bit 0/1: table-ref ili eksplicitni start/end
  u8 secondary_flags        # bit 7: postoji extension deo
  u8 delta_pair_count
  s8 delta_pairs[delta_pair_count][2]
  u16/u32 explicit_start[2] # samo kada je flags.bit0 == 0
  u16/u32 explicit_end[2]   # samo kada je flags.bit1 == 0
  u8 extension[]
}
```

Firmware funkcije na VA `0x01553940` i `0x002e62b4` daju egzaktno pravilo za
prelazak na sledeći subrecord. Osnovna dužina je:

```text
3 + 2 * delta_pair_count
+ (flags.bit0 == 0 ? coordinate_width : 0)
+ (flags.bit1 == 0 ? coordinate_width : 0)
```

`coordinate_width` je 4 B kada su x/y komponente `u16`, odnosno 8 B kada su
`u32`; ovo je širina dve komponente, ne dodatna Z osa. Firmware visitor na VA
`0x01559a60` potvrđuje numeričko pravilo:

```text
absolute_x = bbox_min_x + coordinate_scale * encoded_x
absolute_y = bbox_min_y + coordinate_scale * encoded_y
next_point = previous_point + coordinate_scale * (s8_delta_x, s8_delta_y)
```

Kada je `flags.bit0/bit1` postavljen, početak/kraj se uzima iz coordinate
tabele koristeći edge-descriptor bajt +5/+6; kada je bit čist, par je upisan
iza delta niza. Za ne-poslednji subrecord sa `secondary_flags.bit7`, firmware
pri prelasku koristi `u16 extension_size` i toliko bajtova. Granica poslednjeg
extension dela dolazi iz enclosing edge-offset tabele. Funkcija na VA
`0x0149d144` razlikuje tagged extension tipove 1..19; njihova puna semantika
još nije imenovana.

Automatska inferencija je krenula od 8.704 kandidata, ostavila jedinstvenu
trojku `record_header_base=2`, `subrecord_base=3`, `subrecord_stride=2` posle
četiri realna zapisa, pa je proverila svih 838.433 geometry zapisa. Dobijeno je
903.487 subrecord-a; 226.098 ima extension bit. Nije pronađena nijedna
nevalidna granica. Izvršni validator je `tools/basic_geometry_grammar.py`, a
izveštaj `out/basic_geometry_grammar/report.json`.

Koordinatni prolaz `tools/basic_geometry_decode.py` dekodirao je svih 838.433
edge-a u 903.487 delova, 2.153.761 potpisanih delta-parova i 3.960.735 tačaka.
Svih 717.730 coordinate-table zapisa i sve dobijene tačke nalaze se unutar
cluster bbox-a. Svih 3.336 klastera koristi skalu 4; 3.335 klastera koristi
u16, a jedan u32 komponente. Izveštaj je
`out/basic_geometry_decode/report.json`.

Graph prolaz `tools/basic_graph_export.py` dokazuje da subrecord-i jednog
edge-a nisu alternativne geometrije nego uzastopni delovi: svih 65.054
unutrašnjih spojeva se poklapa tačno. Spajanjem se dobija 838.433 centerline-a
sa 3.895.681 tačkom. Svih 1.676.864 razrešivih node-adjacency veza odgovara
edge endpoint-ima. Četiri eksplicitno zapisana endpoint para razlikuju se od
coordinate-table čvora za 4–12 Mercator jedinica zbog nezavisne kvantizacije;
svaki coordinate-table endpoint se poklapa tačno. Rezultat je
`out/basic_graph_export/report.json`.

### Basic handle 2: edge semantic directory i direktni tekstovi

Firmware put `0x01558164 → 0x01550730 → 0x014a4538` bira treći handle glavnog
Basic klastera. Korpus i firmware zajedno zaključavaju directory config offset
na `6`:

```text
u8  payload_flags
u16 record_data_end              # offset +1; početak cluster footera
u8  text_mode                    # bit0 tag, bit2 secondary, bits3..4 encoding
u8  default_identifier
u8  secondary_mode               # bit0: secondary identifier je prisutan
u16 auxiliary_count              # offset +6

if auxiliary_count > 0:
  u32 auxiliary_entries[auxiliary_count]
  u32 auxiliary_trailer          # 0 u svih 3.335 non-empty slučajeva

u16 edge_record_offset[edge_count]
```

Kada je `auxiliary_count == 0`, edge directory počinje na offsetu `8`; inače
počinje na `12 + 4 * auxiliary_count`. Svih 838.433 pokazivača je iza
directory tabele i pre `record_data_end`. Directory nije sortiran i aliasi su
normalni: 838.433 edge reference vode na 182.377 jedinstvenih recorda.

Spoljni schema descriptor daje record pointer base `3`. To je jedini kandidat
za koji svih 41.671 flag-selected relativnih pokazivača ostaje iza header-a i
unutar tačno omeđenog recorda:

```text
u8  flags
u8  auxiliary_selector           # 0xff ili < auxiliary_count
u8  mode                         # 0 ili 1 u ovom corpusu
u16 section_offset[popcount(flags & 0x3f)]
u8  direct_text_count
direct_text[direct_text_count]
flag_selected_sections[]
```

Granica recorda je sledeći sortirani jedinstveni record offset, a za poslednji
record `u16@payload+1`. Nije dozvoljeno poravnanje: 88.783 record offseta je
neparno. Bits 5..7 nisu viđeni u ovom corpusu; složeniji firmware put za
0x40/0x80 ostaje eksplicitno nepodržan umesto da se nagađa.

Direktni tekst cursor je rekonstruisan iz firmware funkcija `0x014915e8` i
`0x01491fac`. Svaka stavka ima opcioni identifier/tag, jednu primarnu vrednost
i, kada je `text_mode.bit2` postavljen, jednu sekundarnu/fonetsku vrednost.
High bit taga bira alternate variant, a low 7 bitova daju identifier.
`secondary_mode.bit0` dodaje zaseban secondary identifier. Firmware podržava
Latin-1 (`0`), UTF-8 (`1`) i UTF-16LE (`2`); Serbia corpus koristi UTF-8 u
svih 3.336 klastera.

`tools/basic_handle2_text_decode.py` završava cursor tačno na nezavisnoj
granici svake sekcije za svih 182.377 recorda: 271.823 primarna stringa,
262.187 sekundarnih/fonetskih stringova i nula grešaka. Firmware
`0x014915e8` upisuje `tag & 0x7f` kao jezički ID objekta na `+0x30`, a
`tag >> 7` kao alternate/transliteration flag na `+0x38`.

Basic `world` blok direktno zatvara numeričku semantiku. Njegov directory je:

```text
u16 country_count                 # offset +3
u8  pointer_width_minus_one       # offset +5
self_relative_pointer countries[] # offset +6, širina 1..4 B

country trailer:
  char country_code[2..3]
  u8   official_language_count
  u8   official_language_id[official_language_count]
  u8   zero_padding[]
```

Na Serbia ulazu `world` je `0x02d1049d..0x02d11dd0`; svi recordi i padding
prolaze validator. Traileri su `MNE\0 01 30`, `SRB\0 01 21`,
`BIH\0 02 1e 21` i `RKS\0 02 21 1f`. Albania cross-check ima
`AL\0 01 1f`. Zajedno sa native country-name tagovima i regionalnim korpusom
to daje:

| ID | Jezik | Direktna world-country veza |
|---:|---|---|
| 30 (`0x1e`) | Bosnian | BIH official; `Bosna i Hercegovina` |
| 31 (`0x1f`) | Albanian | AL/RKS official; `Shqipëria`, `Kosovë` |
| 33 (`0x21`) | Serbian | SRB/BIH/RKS official; `Србија` |
| 48 (`0x30`) | Montenegrin | MNE official; `Crna Gora` |

Firmware `FUN_00f2d8fc` čita isti count+niz kao official-language listu.
`tools/basic_world_country_languages.py` izvodi sve offsete i hash-eve u
`out/basic_world_country_languages/`.

`tools/basic_handle2_name_profile.py` i `basic_name_semantics.py` grupišu
271.823 fizičke stavke u 151.818 logičkih imena. Svih 120.005 alternate
stavki neposredno prati base istog ID-a; nema orphan ili mismatch slučaja.
To daje 120.005 base→transliteration parova i 31.813 samostalnih albanskih
base stavki. Na edge nivou ima 554.508 logical-name i 440.790
transliteration-pair referenci.

Izbor pisma je consumer politika dokazana u firmware VA `0x012a97e0`: ako
base jezički ID nije u konfigurisanom transliteration skupu, koristi se base;
ako jeste, upareni alternate je obavezan i bira se. Ne postoji dokaz da niz
zvaničnih jezika ili numerička vrednost ID-a određuju univerzalni preferred
jezik/alias. `basic_graph_export.py` zato čuva sve `name_candidates` i
`logical_names`, a opcija `--transliterate-identifier` primenjuje samo
dokazani izbor base/alternate.

Važna korekcija: prioritetna petlja `0x014a3ec0` pripada odvojenoj
header-flag-`0x02` listi brojeva puteva (`E-851`, `R7`, `N9`, ...); ona ne
rangira street-name ID-jeve `30/31/33/48`.

Serbia rezultat je 838.433 edge-a, 717.730 node-a i 838.433 geometry zapisa.
Svih 3.336 geometry bbox-ova tačno odgovara ID indeksu, svaki geometry count
odgovara topology edge count-u, a sve reference koje ostaju unutar glavnog
triple-handle corpusa prolaze edge→node i node→edge proveru. Van tog corpusa
ostaje samo 120 endpoint i 118 adjacency referenci; one se čuvaju kao
nerazrešeno poreklo, ne odbacuju se. Izvršni dokaz je
`tools/basic_semantic_probe.py`, a rezultat `out/basic_semantic_probe/report.json`.

Tagged extension delovi geometry subrecord-a i završni `trailing_attributes`
deo node zapisa još se čuvaju kao raw source sa offsetom, veličinom, hash-em i
firmware provenance-om. Osnovne geometry tačke više nisu raw: numerički su
dekodirane i globalno proverene.

Fields `0x140..0x144` ne opisuju ovaj 38B indeks niti `CombinedDesc`.
Firmware ih mapira u petobajtni TMC/location format config `[15,2,6,1,5]`:
fixed header 15, location subrecord offset 2, šestobajtni pair-table prefix,
jednobajtni prefix za 3B indeks i petobajtni area/location index stride.
Consumer family je oko Ghidra VA `0x012a9b84..0x012af744`; projekat ima
image-base slide `+0x10000`, pa se za raw ELF/objdump oduzima `0x10000`. Ovo
će se koristiti pri semantičkom dekodiranju finalizer sekcija 1/2.

### Basic single-handle spatial šuma `0xb3`

Metadata field `0xb3` sadrži deset trojki:

```text
[tree_depth, root_or_leaf_offset, serialized_size]
```

Kod depth 1 offset direktno pokazuje na leaf. Kod depth 2 pokazuje na root:

```text
u32 child_count
child_count * { s32 bbox[4], u32 child_leaf_offset }
```

Leaf ima 12-bajtni link header i 24-bajtne zapise:

```text
u32 link_a
u32 link_b
u32 count
count * {
  s32 bbox[4]
  u32 compressed_offset
  u32 packed                 # low16=stored_size, high16=aux 0..4
}
```

Tri depth-2 root stranice su `0x412C2` (3 deteta), `0x516A6` (9) i
`0x954DA` (35). Ukupno 54 leaf stranice daju 15.676 jedinstvenih validnih
LZMA handle-a. Zajedno sa 10.008 ID handle-a čine 25.684 payload-a; osam
world/tail handle-a dopunjava prvi potpuno kontigvan lanac od 25.692 toka,
`0x990C2..0x21532BC`.

### Basic final spatial indeks `0x13e`

Metadata `0x13e=[0x97F82,2,44]` opisuje root sa dva deteta. Leaf stranice su
na `0x9579A` (292 zapisa) i `0x97796` (72 zapisa):

```text
u32 link_a
u32 link_b
u32 count
count * {
  s32 bbox[4]
  u32 compressed_offset
  u32 compressed_size
  u32 key
}
```

Svih 364 `(key, offset, size)` zapisa tačno se poklapa sa 364 zapisa u
field-`0x13f` ID indeksu. To su dva pogleda — spatial i ID — na isti finalni
kontigvan LZMA lanac `0x2AF4BE3..0x2CF8559`.

### Basic key indeks `0x13f`

Metadata field `0x13f` pokazuje na:

```text
u32 count
count * { u32 key, u32 compressed_offset, u32 compressed_size }
```

Serbia uzorak ima 364 ključa `0..363`; svi targeti su validni LZMA streamovi.
Firmware koristi binary search nad ovim zapisima.

Svi potvrđeni Basic indeksi zajedno imaju 33.092 reference ka 26.056
jedinstvenih direktno indeksiranih kompresovanih payload-a. Dual-spatial je
podskup triple-ID indeksa; final-spatial i `0x13f` su identični setovi.

## Kontigvni klasteri i root footer-i

Strict LZMA prolaz, uz egzaktne decoder EOF granice, deli Basic fajl
na 9.051 kontigvni klaster i 9.050 međuprostora. Standardni međuklasterski
root čvor ima sledeći posmatrani bajtni raspored, koji dekoder trenutno
modeluje kao:

```text
u8 child_count
u8 reserved[6] = {0}
child_count * {
  u8  type_flags
  u32 child_offset
  u16 child_stored_size
}
```

Svi lokalni `child_count` iznosi su 1..33, pa bajtovi ne razlikuju ovaj model
od `u32le child_count + u8 reserved[3]`. Širina count polja zato ostaje
otvorena do direktne potvrde firmware consumera; dekoder namerno prihvata
samo posmatrani kanonski oblik sa šest nultih bajtova iza low count bajta.
Statička provera K3663 parsera nije pouzdano identifikovala consumer ovog
compact formata. Ghidra `FUN_0029c000` (`0x0029c000`, raw ELF `0x0028c000`)
zaista sklapa `u32le` iz četiri bajta, ali čita zaseban 8-bajtni B-tree page
header i nije dokaz za ovaj footer. `.gnu_debuglink` traži
`libPathfinderApp.so-20160718160238.sym`, koji nije prisutan u firmware-u ni
lokalnim ulazima, pa simbolička potvrda nije dostupna.

Svaki `(child_offset, child_stored_size)` tačno pokazuje na validan LZMA tok.
U Basic fajlu 9.040 gapova su čisti footer-i; još jedan veliki specijalni gap
počinje validnim footer-om. Ukupno je 9.041 footer i 9.242 reference. Deset
gapova sadrži dodatne/raw strukture. Dominantni tipovi su `0x21`, `0x1f` i
`0x30`.

Četiri specijalna raw bloka počinju potvrđenim internal B-tree tabelama na
`0x2281F32`, `0x28F2E9E`, `0x2936D7A` i `0x2938EDF`, sa redom 40, 166, 25 i
2 deteta:

```text
u32 child_count
u32 reserved = 0
(child_count - 1) * { CombinedDesc child, u32 separator_key }
CombinedDesc final_child

CombinedDesc {
  u32 block_offset
  u32 total_stored_size
  u32 middle_size
  u32 reserved = 0
  u32 finalizer_stored_size
}
```

Za svaki descriptor važi:

```text
lead_size       = total_stored_size - middle_size - finalizer_stored_size
lead_offset     = block_offset
middle_offset   = block_offset + lead_size
finalizer_offset= block_offset + total_stored_size - finalizer_stored_size
```

Svih 233 deskriptora je validirano. Sva tri prisutna segmenta su zasebni
canonical LZMA streamovi: 233 lead + 226 middle + 230 finalizer, ukupno 689
jedinstvenih handle-a. Middle segmenti imaju 665.962 B stored i 1.115.682 B
raspakovano. Nisu raw regioni i već su sadržani u glavnom source payload-u.

Od 230 finalizer streamova, 151 se raspakuje u jedan nulti bajt. Preostalih
79 počinje direktorijumom sekcija:

```text
u8 section_count
section_count * { u8 section_type, u32 section_offset }
```

U ovom Basic uzorku obrasci su 59 puta `(5,4,1,2)` i 20 puta `(4,2)`.
Sekcije tipa 4 i 5 su potpuno zatvorene:

```text
u16 slot_count
slot_count * {
  u32 compressed_offset
  u16 stored_size
  u8  flags
}
```

Nulti slot je sedam nula. Od 9.208 slotova, 7.618 je prazno; preostalih 1.590
referenci pokazuje na 1.590 različitih validnih LZMA streamova. Tip 4 daje
1.347, a tip 5 još 243 reference. Svi posmatrani flags bajtovi su nula.
Sekcije 1/2 su TMC/location sadržaj; njihov detaljni record model ostaje
sledeći semantički sloj.

Za potvrđeni strict scan scope, Basic segmentacija je zatvorena do bajta:

```text
25.692 streama  0x0990C2..0x21532BC  direktni prefix/world lanac
39.471 stream   0x21532BC..0x2AF4BE3 klastersko telo sa footer-ima/raw blokovima
364 streama     0x2AF4BE3..0x2CF8559 final spatial/ID lanac
```

Zbir je 65.527 streamova, 44.487.407 B kompresovano i 82.275.083 B
raspakovano. GlobalPOIIndices istim pravilom daje 7.069 streamova u 522
klastera, uključujući završni footer ispred tail blokova.

`export-source` zapisuje potpuno proverljiv storage/source layer za taj scan
scope kao
`manifest.jsonl + payloads.bin/blocks`, sa klasterom, originalnim offsetom,
veličinama, hash-evima, index provenance i root tipovima za svaki stream.
Manifest schema v6 razdvaja ceo stored wrapper
(`wrapper_offset/wrapper_size`, `sha1_stored`) od čistih codec bajtova
(`codec_stream_offset/codec_stream_size`, `sha1_compressed`); polje
`compressed_size` je alias za `codec_stream_size`.
`index_references.jsonl` čuva sve reference, uključujući duplikate između
dual/triple i spatial/key pogleda. `layout.json` čuva i
CombinedDesc/finalizer-directory veze.

## Basic geometry road-attribute lanac

Svih 226.098 geometry delova sa extension-om prolazi isti format. Ako bit 7
subrecord flag-a nije postavljen, extension počinje tačnim `u16le payload_size`;
finalni subrecord (bit 7 postavljen) koristi granicu enclosing recorda bez tog
prefiksa. Atributi su lanac; bit 7 type bajta znači da sledi još jedan tag, a
low 7 bitova je `EXTT` tip 1..19.

Firmware enum redosled je:

```text
 1 SIMPLE_SPEED_LIMIT           11 Z_ORDER_INFO
 2 EXTENDED_SPEED_LIMIT         12 Z_VALUE_INFO
 3 LANE_CONNECTIVITY            13 NUMBER_OF_LANES
 4 JUNCTION_VIEW                14 SIMPLE_PASSING_RESTRICTION
 5 THROUGH_ROUTE_INFO           15 EXTENDED_PASSING_RESTRICTION
 6 SIGN_INFO                    16 LANES
 7 GRADE_CATEGORY               17 ADDITIONAL_GEOMETRY
 8 STRAIGHT_ON                  18 TRAFFIC_SIGNAL_INFO
 9 ATTRIBUTE_EX1                19 UNKNOWN
10 TOLL_GATE_INFO
```

Direktno potvrđeni payload-i:

```text
tag 1:  {type, u8 speed_value}
tag 2:  {type, packed_size, direction_and_subtype, speed_value, ...}
tag 13: {type, u8 lane_count_at_node_a, u8 lane_count_at_node_b}
tag 14: {type}                                      # marker
tag 15: {type, flags, ...}                          # bit0 A->B, bit1 B->A
                                                      bit2 detailed records
                                                      bits3..5 record count
tag 16: {type, packed_count, N * u8 lane_record[4]} # N=packed_count>>4
```

Tag 2 koristi bitove 0/1 trećeg bajta za A→B/B→A i `byte2>>2` za subtype.
Bajt 3 je speed vrednost. Kada je subtype 7, `byte1>>5` je broj dvobajtnih
condition parova od offseta 5, a source selector dolazi posle poslednjeg para;
inače je source selector byte 4. Subtype 0 je firmware-potvrđen kao
`SLT_GENERAL`; ostali nazivi i jedinica vrednosti ostaju neimenovani.
Simple-speed jedinica takođe nije još nezavisno dokazana i zato se čuva kao
originalna vrednost uz `unit=null`. Tag 16 četvorobajtni slog je field-level
podeljen, ali njegovi javni pod-enumi nisu imenovani. Firmware VA `0x0097f054`
direktno koristi record byte-0 low nibble i bitove 4/5, byte-1 low-nibble kod,
byte-2 high-nibble category kod i byte-3 low-3 kod. Category kodovi 0..7
mapiraju se na maske `0,1,4,32,5,33,128,128`; svih 39.538 slogova ovog korpusa
je u tom opsegu i izvezeno kroz `decode_lanes()`, sa preostalim nibble-ima i raw
bajtovima. Descriptor byte 3 bits 0/1 daju static/base
A→B/B→A pristup; bytes 7/8 low 13 bits daju base extended-automotive mask, a
bit 14 dynamic-extension marker. `active_bit_indices` lossless razdvaja masku
na bitove 0..12; corpus aktivira 0–5 i 7–12, dok bit 6 nema nijedan primer.
Originalni descriptor, ceo tag i extension
ostaju u graph source-u kao lossless provenance.

Topology dynamic sekcija ima firmware-potvrđeno framing pravilo:

```text
topology[12:15] = u24le directory_offset       # 0 = nema direktorijuma
directory       = u8 entry_count
                  entry_count * {u8 type, u16le payload_offset}
payload_offset  = relativno od početka direktorijuma
type 5 payload  = u8 count + count * u8 record[4]
type 5 record   = {u8 local_edge, u8 flags, u16le low_value}
value           = (low_value | ((flags & 1) << 16)) << (4 if flags & 2 else 0)
type 3 payload  = {u16 count, u8 aux_count, u16 payload_end,
                   count * {u8 local_edge, u8 selector, u16le condition_offset},
                   shared condition objects...}
```

Lookup je firmware VA `0x014a67e0`, a type-5 expression VA `0x014a69e8`.
Caller VA `0x00977af8` upisuje `value*100`, ali javno ime/jedinica tog polja
još nisu dokazani. Full corpus ima 868 direktorijuma, 1.178 entry-ja, 1.819
type-5 slogova i nijednu framing/edge-key grešku. Type 3 je dokazani ulaz
time-dependent direction consumera VA `0x014a6a88`; unpacker VA `0x014a9858`
potvrđuje 308 edge selector slogova i 56 deljenih condition objekata. Selector
bitovi 0/1 su A→B/B→A, `(flags&0x0c)>>2` je query grupa, a
`(flags&0x70)>>4` timezone-table indeks. Condition flagovi redom uključuju
year range, month range/12-bit mask, day-of-month range/31-bit mask, 7-bit
weekday masku i start/end 15-minutne slotove. Sva polja i tačna potrošnja
bajtova su provereni na svih 308 slogova; korpus koristi samo timezone indeks
0. Firmware-policy VA `0x014a94f0` je implementiran, dok stvarni runtime
timezone/query ulaz ostaje posao adaptera.

Dokazne funkcije su VA `0x002e1c9c`, `0x002f0484`, `0x002e3a34`,
`0x0097f054`, `0x0097cb48` i `0x008ce240`. Full-corpus stage je
`tools/run_basic_road_attributes_stage.py`; canonical report je
`out/basic_road_attributes_stage/report.json`.

## Otvoreno

- preostala semantika Basic tagged extensions, node trailing atributa i
  attribute sekcija; handle-2 jezički ID-jevi, base/transliteration pravilo,
  direktni tekstovi, edge/node/geometry granice, topology veze i numeričke x/y
  tačke su potvrđene;
- semantičko parsiranje sadržaja deset posebnih Basic gapova/raw ostataka;
- srednji spatial indeks u MIB2 `AdvancedMap2D` i završni 530-entry indeks;
- `GlobalPOIIndices` strukture;
- semantički kompletirati graph source consumer/UI izborom jednog jezika ili
  aliasa, runtime povezivanjem type-3 time-dependent direction pravila,
  preostalim tag-2 extended-speed subtype nazivima/jedinicom, javnim imenima
  dekodiranih lane category maski,
  vehicle-class restrikcijama, manevrima i ADAS svojstvima;
- Orion/ATLAS writer: fizičko kodiranje već pripremljenog clothoid source-a,
  kolone, indeksi i determinističko ponovno pakovanje iz validiranog graph
  source-a.

Ne treba tvrditi da je PSF goli Zserio/NDS stream. Aktivni format u ovom
firmware-u je PSF2DDTM, a praktični put je rekonstrukcija skladišnog i
record sloja iz `libPathfinderApp.so`.
