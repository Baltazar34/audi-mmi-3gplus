# Claude handoff — Audi MIB PSF60 → MMI 3G Plus

Checkpoint: 2026-09-02. Ovaj dokument je operativni nastavak rada, ne nova
specifikacija. Tvrdnje označene kao završene potvrđene su firmware-om, punim
korpusom i testovima. AdvancedRouting/ADAS framing je završen; njihova
unutrašnja javna semantika nije.

## Cilj

Cilj je dekodiranje MIB `PSF2DDTM`/`60DREID4ADAS7` mapa i pravljenje
proverljivog source/adapter sloja za MMI 3G Plus Orion/ATLAS. Ulazne arhive su
originalni izvor; sva obrada je lokalna.

Korisnik želi da se analiza izvršava kroz trajne skripte koje:

- same prolaze ceo korpus;
- ispisuju kratak progress u realnom vremenu;
- prekidaju rad na prvoj neusaglašenosti;
- pišu JSON/NDJSON izveštaje i `CHECKSUMS.sha256`;
- imaju unit/integration testove;
- ne zamenjuju dokaz nagađanjem ili ručnim jednokratnim analizama.

## Kanonski ulazi

### MHI2 firmware

- Arhiva: `$MHI2_ARCHIVE`
- SHA-256: `393619c139e606efde32ad46d5c1ad997b76d18218ec82ed96128be07cfef975`
- Navigacioni parser u radnom cache-u:
  `$MHI2_APP50/navigation/libPathfinderApp.so`
- Parser SHA-256:
  `636b7d1440938928d97435efc3897cf5baed0b1f768ad03f7efd0b6b109c4ee9`

### MIB mapa

- Arhiva: `$MIB_ARCHIVE`
- SHA-256: `4a390301e165a011c3b038c5f17ec42786d6caeb7edb3d176abeed6b6fbb8fd6`
- Primarni PSF u radnom cache-u:
  `$MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf`
- Format: `PSF2DDTM`, verzija `60DREID4ADAS7`.

Putanje pod `/private/tmp` mogu nestati posle restarta. Originalne arhive u
`Downloads` su trajni izvor. Potpun inventar, uključujući M.I.B. offload paket
i prethodni Claude/MMI3G projekat, nalazi se u `docs/INPUT_INVENTORY.md`.

## Zatvoreni slojevi

### 1. PSF storage/source

`tools/psf_decode.py` čita PSF omotač, metadata, poznate cluster indekse i
firmware-kompatibilne LZMA-Alone/zlib streamove. Kanonski source layer je
`out/serbia_basic_source/` sa 65.527 manifest redova i 82.275.083 B
raspakovanih blokova. Wrapper i codec-stream hash/provenance čuvaju se
odvojeno.

### 2. Topologija i geometrija

Završeni alati:

- `tools/basic_semantic_probe.py`
- `tools/basic_geometry_grammar.py`
- `tools/basic_geometry_decode.py`
- `tools/run_basic_geometry_re.py`

Potvrđeno nad celim Serbia korpusom:

- 3.336 glavnih Basic klastera;
- 838.433 edge deskriptora;
- 717.730 node zapisa;
- 838.433 geometry zapisa;
- 903.487 geometry delova;
- 3.960.735 dekodiranih geometry tačaka;
- 3.895.681 tačka u spojenim centerline-ovima;
- sve razrešive node/edge reference odgovaraju u oba smera;
- svi coordinate-table endpoint-i odgovaraju topološkim čvorovima;
- svih 65.054 spojeva geometry delova je kontinuirano.

Endpoint oznake `a` i `b` trenutno čuvaju firmware slot redosled. One **nisu**
dokaz putnog smera. Četiri eksplicitno zapisana endpoint para razlikuju se od
kanonske node koordinate za 4–12 Mercator jedinica zbog nezavisne kvantizacije;
topološki node ostaje autoritativan.

### 3. Handle-2 recordi i tekst

Završeni alati:

- `tools/basic_handle2_directory.py`
- `tools/basic_handle2_text_decode.py`
- `tools/run_basic_handle2_re.py`

Potvrđeno je 182.377 jedinstvenih semantic recorda. Svih 838.433 edge
referenci i svih 41.671 flag-selected pokazivača ostaje u validnim granicama.
Direktni `SDString` cursor dekodira 271.823 primarna i 262.187 sekundarna/
fonetska stringa bez greške.

Ključni firmware dokaz:

- VA `0x014915e8`: `tag & 0x7f` upisuje language identifier, a high bit taga
  je alternate/transliteration flag;
- VA `0x01491fac`: nastavak direktnog string cursor-a;
- VA `0x012a97e0`: consumer izbor base/transliteration oblika;
- `FUN_00f2d8fc`: čita official-language count+niz iz country recorda;
- `FUN_00f4b764`: proverava članstvo language ID-a u tom nizu.

Ghidra projekat je `/private/tmp/ghidra_pf/Pathfinder`, program
`libPathfinderApp.so`. Ghidra VA ima image-base slide `+0x10000` u odnosu na
raw ELF/objdump VA. Ne mešati ta dva adresna prostora.

### 4. Stavka 1 — jezici, imena i transliteracija

Završeni alati:

- `tools/basic_world_country_languages.py`
- `tools/basic_handle2_name_profile.py`
- `tools/basic_name_semantics.py`
- `tools/basic_graph_export.py`
- `tools/run_basic_name_stage.py`
- `tools/run_basic_identifier_crosscheck.py`

Direktno potvrđena mapa je:

| ID | Jezik | World-country dokaz |
|---:|---|---|
| 30 (`0x1e`) | Bosnian | BIH official language |
| 31 (`0x1f`) | Albanian | AL/RKS official language |
| 33 (`0x21`) | Serbian | SRB/BIH/RKS official language |
| 48 (`0x30`) | Montenegrin | MNE official language |

Svih 271.823 fizičkih tekstualnih stavki daje 151.818 logičkih imena. Svih
120.005 alternate zapisa neposredno prati base istog ID-a; nema orphan ili
mismatch slučaja. Firmware izbor je implementiran tačno: base se koristi ako
ID nije u consumer transliteration skupu; ako jeste, upareni alternate je
obavezan i bira se. Različiti jezici i aliasi ostaju sačuvani — nije izmišljen
globalni preferred-language redosled.

Važna korekcija: `FUN_014a3ec0`/VA `0x014a3ec0` rangira odvojene route-number
kandidate (`E-851`, `R7`, `N9`, ...). To nije street-name preference funkcija.

Kanonski graph izlazi:

- `out/basic_graph_export/` — base prikaz;
- `out/basic_graph_export_latin/` — transliteracija za ID 30, 33 i 48;
- `out/basic_name_stage_latin/report.json` — zbirni autonomni dokaz;
- `out/basic_identifier_crosscheck/crosscheck_report.json` — Albania/Bosnia
  archive cross-check.

Latin profil ima 554.508 odabranih logical-name edge referenci: 113.718 base
referenci i 440.790 transliteracija, bez missing-transliteration slučaja.

## Stavka 2: izvršeni road atributi i tačna granica nastavka

Napravljena su oba autonomna runner-a i canonical izlaz prolazi sve interne
cross-check provere:

- `tools/run_basic_road_attributes_re.py` — ponovljiv Ghidra decompile/xref;
- `tools/run_basic_road_attributes_stage.py` — full-corpus profiler + graph
  integracija + međusobna provera + checksumi;
- `tools/basic_dynamic_attributes.py` — firmware-identičan topology dynamic
  directory i type-5 edge-record decoder;
- `tools/basic_dynamic_attributes_profile.py` — autonomni full-corpus dynamic
  profiler;
- `out/firmware_re/basic_road_attributes/`;
- `out/basic_road_attributes_profile/report.json`;
- `out/basic_road_attributes_stage/report.json`;
- `out/basic_road_attributes_stage/dynamic_attribute_profile/report.json`;
- `out/basic_road_attributes_stage/graph_export/edges.jsonl`.

Potvrđeni firmware ugovor:

- descriptor byte 3 bit 0 = static/base A→B allowed, bit 1 = B→A allowed;
  direktni consumer VA `0x002e1c9c`;
- geometry tag 1 = simple speed-limit vrednost; skladišni consumer
  `0x002f0484`, javni API consumer `0x002e3a34`;
- geometry tag 2 = extended speed-limit. Bajt 2 nosi A→B/B→A bitove i
  subtype, bajt 3 vrednost, a subtype 7 promenljivi niz condition parova i
  source selector; consumeri `0x0097e934`, `0x0097e848` i `0x0097e4a0`.
  Firmware dijagnostika nezavisno potvrđuje samo subtype 0=`SLT_GENERAL`;
- firmware `EXTT` redosled direktno daje tagove 13=`NUMBER_OF_LANES`,
  14=`SIMPLE_PASSING_RESTRICTION`, 15=`EXTENDED_PASSING_RESTRICTION`,
  16=`LANES`;
- tag 13 payload byte 1/2 su broj traka na node-A/node-B kraju dela puta;
  consumer VA `0x0097f054`;
- tag 14 je payload-free passing marker; tag 15 bitovi 0/1 daju A→B/B→A,
  bit 2 bira detaljne slogove i bitovi 3..5 njihov broj; consumer
  `0x0097cb48`;
- tag 16 ima `2 + 4*N` format, `N=byte1>>4`; `decode_lanes()` izlaže sva
  firmware-consumed nibble/flag polja i direktnu category-mask normalizaciju
  stored kodova 0..7, uz raw payload;
- descriptor bytes 7/8 low 13 bits su base extended-automotive mask, a bit 14
  označava dynamic extension; javni consumer VA `0x008ce240`. Source izlaže
  i `active_bit_indices` 0..12 bez nagađanja javnih imena;
- topology byte 12..14 je `u24le` pokazivač na dynamic direktorijum; njegov
  format je `u8 count` pa ponovljeni `(u8 type, u16le relative_offset)`;
  lookup consumer VA `0x014a67e0`;
- type 5 je `u8 count + N*4` edge-keyed numerička override tabela. Firmware
  VA `0x014a69e8` dekodira 17-bitnu vrednost i opcioni `<<4`; caller
  `0x00977af8` rezultat upisuje kao `value*100`. Javno ime i jedinica još nisu
  dokazani i zato se ne nazivaju speed/length napamet.

Full-corpus rezultat: 3.336 klastera, 838.433 edge-a, 903.487 geometry dela,
226.098 delova sa tagged atributima, bez ijednog invalid extension-a ili
graph mismatch-a. Raspodele su 117.458 edge-a sa 156.406 simple-speed
vrednosti, 61.618 extended-speed vrednosti na 23.844 edge-a, 1.632
number-of-lanes, 50.617 simple passing, 9.942 extended passing i 15.614 lane
atributa sa ukupno 39.538 četvorobajtnih slogova. Svi lane byte-2 high-nibble
kodovi su 0..7, pa korpus prolazi direktnu firmware switch mapu u maske 0, 1,
4, 5, 32, 33 i 128 bez runtime remap tabele. Extended-speed subtype raspodela
je 0:47.666, 1:122, 2:5.824,
3:271, 4:1.295, 7:4.016 i 8:2.424. Smer: 13.884 A→B-only, 13.908 B→A-only,
791.644 oba i 18.997 nijedan static direction.

Dynamic corpus je takođe kompletno validiran: 868 klastera imaju direktorijum,
ukupno 1.178 typed payloada i svih 3.324 descriptor dynamic markera; type
raspodela je 1:59, 2:189, 3:42, 4:12, 5:241, 8:72 i 9:563. Type 5 sadrži
1.819 validnih edge slogova; type 9 ima 6.140 strukturno potvrđenih
četvorobajtnih slogova, ali mu polja ostaju raw. Firmware vehicle decoder traži
type 7, a ovaj korpus nema nijedan type-7 direktorijumski unos.

Type 3 je dodatno razdvojen po firmware unpackeru VA `0x014a9858`: aktivni
schema profil je `u16 count, u8 aux_count, u16 payload_end`, pa `N * {u8 edge,
u8 selector, u16 condition_offset}`. Svih 42 tabela daje 308 validnih edge
slogova i 56 deljenih condition objekata; `aux_count=0` i `payload_end=len` u
celom korpusu. Selector bitovi 0/1 daju A→B/B→A, bitovi 2..3 biraju query
grupu, a bitovi 4..6 timezone-table indeks. Godina, mesec, dan u mesecu,
weekday maska i start/end 15-minutni slotovi condition objekta su dekodirani
po VA `0x014aa33c..0x014aa5f8`; svih 308 slogova koristi timezone indeks 0.
`dynamic_selector_action()` i `time_condition_matches()` implementiraju
firmware query-policy i lokalni kalendarski evaluator, uz lossless raw bajtove.

Tačna otvorena granica unutar stavke 2:

1. nezavisno dokazati jedinicu simple-speed vrednosti (korpus izgleda kao
   km/h, ali source je namerno ne imenuje);
2. povezati type-3 evaluator sa stvarnim MMI 3G+ runtime timezone/query-mask
   ulazom; extended-speed source je pronađen u geometry tagu 2, ali preostale
   subtype nazive i jedinicu vrednosti još treba nezavisno dokazati (type 5 i
   dalje nije imenovan bez dodatnog dokaza);
3. nezavisno dokazati javna imena već dekodiranih `LANES` category maski i
   preostalih numeričkih polja; framing, sva consumed polja i corpus vrednosti
   su završeni;
4. dokazati pojedinačna javna značenja automotive bitova i vehicle-class
   restriction rezultate. Bit decomposition je završen: prisutni su bitovi
   0–5 i 7–12, bit 6 se ne pojavljuje, a svaki edge čuva masku i aktivne indekse.

AdvancedRouting, ADAS i Orion clothoid podatke držati odvojeno od Basic road
atributa. Stari MMI3G/Orion numerički enum-i mogu pomoći kao rečnik, ali se ne
smeju preslikati na PSF60 bez direktnog firmware dokaza.

## Pre-writer AdvancedRouting, ADAS i clothoid checkpoint

Završeni autonomni alati:

- `tools/pre_writer_layers.py` — strogi lossless cluster decoder;
- `tools/pre_writer_layers_profile.py` — puni corpus profil i fingerprint;
- `tools/pre_writer_layers_export.py` — Basic/AdvancedRouting/ADAS edge join;
- `tools/run_pre_writer_layers_re.py` — reproducibilni firmware decompile,
  xref i string-xref batch;
- `tools/orion_clothoid.py` i `tools/orion_clothoid_export.py` — geometrijski
  source pre fizičkog writera.

Potvrđeni AdvancedRouting format je `u8 count, u16le metadata, count*u16le
offsets, records`. Svih 3.342 streamova daje 839.501 record: 838.313 regularno
vezanih za Basic edge, 120 Basic edge-a bez recorda i 1.188 recorda u sedam
supra cluster ID-jeva `12608912..12608918`. Najčešći record ima 5 B, ali
decoder poštuje direktorijum i ne pretpostavlja fiksnu veličinu.

Potvrđeni ADAS format je `u8 count, u16le data_offset, u32le decoded_size,
variable-length size table, records`. Size kod je jedan bajt ispod `0x80`,
inače `((first&0x7f)<<8)|second`. Svih 3.336 klastera daje tačno 838.433
recorda, po jedan za svaki Basic edge; 49.651 record koristi dvobajtnu
veličinu. Firmware `FUN_009e6d10` dokazuje da se Base, Complete i ADAS
container spajaju. Direktni ADAS izvori uključuju scalar/mixed property puteve
i profilne workere `FUN_009df8fc`/`FUN_009e0ea0`; javna imena i jedinice
numeric attribute ID-jeva nisu izmišljeni.

Kanonski source je `out/pre_writer_layers_source/edge_layers.jsonl` sa 838.433
reda i SHA-256
`1e7d4843a22175f7eb5a8b77243bc41baef441debaa7f228072fe5d5f7e0b565`.
Supra source je `advanced_routing_supra.jsonl`, 1.188 redova, SHA-256
`5a687da0b2d7970d862e522e963425b833ea378d1e4fddb0974abec08319a70c`.

Clothoid adapter validira svih 838.433 edge-a, 3.895.681 source tačku i
3.057.085 non-zero krakova. Svaki krak je tačan specijalni Euler spiral
segment `kappa=0`, `dkappa=0`; 163 zero-length kraka se uklanja, endpoint
roundtrip greška je 0.0. Ovo čuva geometriju 1:1 po verteksima, ali ne tvrdi
tangent continuity na uglovima. Fizičko Orion column kodiranje ostaje writer.

Tačna otvorena granica pre writera je semantičko imenovanje/konverzija
AdvancedRouting i ADAS unutrašnjih recorda. Raw source je 1:1 i stabilan, ali
ga nije bezbedno tretirati kao već prevedene Orion `ManoeuvrePart` ili ADAS
kolone.

### Ciljna Orion/PSD provera posle ovog checkpoint-a

`tools/orion_psd_reference_profile.py` je pokrenut read-only nad originalnim
3G Plus `PSD3` (`APN221EU22093P1664a.5_1.2.ATLAS`). Puni scan u
`out/orion_psd_reference_full/` pokriva svih 43.402 blokova / 842.777.616 B,
42.081 uspešno raspakovan deo i 835 neuspeha, svi na blokovima `CONTAINER` sa
`LZMAError: Corrupt input data`. Strogi parser prepoznaje svih 42.066 logičkih
šema i fizičkih tabela; svih 649.210 codec bajtova je `1`, svih 42.066 payload-a
ima tačan kraj i prolazi split→assemble proveru identično bajt-po-bajt. Zato
writer sme konzervativno da emituje samo code 1 i ne mora da reprodukuje režime
2/3.

Novi `parse_logical_schema` reprodukuje NavCore `parseDescriptions` format.
Checkpoint od 3.000 blokova (`out/orion_psd_reference/`) daje 2.999 logičkih
šema i 2.999 tačnih header→descriptor→codec→payload spojeva. Ranijih 17 fallback
tabela sadrži fizički `kind 3` descriptor od 12 B. Prvo dodatno `u32` polje je
indirect count, ne offset; svih 20.250 takvih delova na punom fajlu ima tačno
jednog skrivenog logical-member kandidata i nula count/size odstupanja.
`tools/orion_column_codec.py` sadrži LSB-first reader, type width mapu,
code-1 layout/assembler/round-trip proveru i tačan code-3 header. Važna ispravka: code 3 čita
5-bitnu signed širinu, dictionary count i 8-bitni nested codec, zatim
rekurzivno zove `CDecompression::create`; nije prost niz vrednosti.

Ponovljivi firmware stage je `tools/run_orion_column_codec_re.py`, artefakti i
checksum-i su u `out/firmware_re/orion_column_codec/`. Runner sada automatski
izvlači i `parseDescriptions`, `createTables`, `loadIndexArray` i type→part-count
helper. `FUN_08335a58` vraća 2 za `0x90`/`0xa0`, 1 za `0xb0`, a parser forsira
1 za `0xc0`/`0xd0`; optional članu dodaje dva sintetička in-memory dela.
Corpus pravila pokrivaju array-composite deo, deljeni class/structure `0x90`
deo i `VidTable` optional scalare. Svih 42.066 tabela grupisano je do
`(composite, member, part_index)`, a schema + descriptor tabela + payload daju
identičan decoded chunk pri reserijalizaciji.

Prvi novi object payload sada generiše `tools/orion_object_writer.py`. Skripta
čita MIB graph `nodes.jsonl`, pretvara WGS84 longitude/latitude u signed
`degree × 10^7`, dodaje konzervativni `Height=0` i pravi novu decoded Orion
`Map/PointLlh` šemu sa tri native `0x35`, codec-1 kolone. Sama ponovo parsira
izlaz, grupiše sva tri člana, dekodira vrednosti i zahteva byte-identical
schema/table/chunk round-trip. Kanonski lokalni rezultat je
`out/orion_point_llh_writer/`: svih 100 trenutno izvezenih node redova, binary
1.303 B, `data_offset=103`, payload 1.200 B i šest od šest self-checkova
`true`; svi SHA-256 checksumovi prolaze. Ovo još nije ATLAS blok: header reči
2..4 imaju eksplicitnu privremenu vrednost nula, a kompresija, catalog/index,
apsolutno postavljanje i container checksumovi tek slede. Sledeća tačka rada
je reference/object graph writer (`NodeRoadElement`, `From/To`), pa ATLAS
container/index writer.

Naredni reference podkorak je takođe zatvoren lokalnim dokazom.
`tools/orion_schema_extract.py` read-only nalazi prvi kompletan graph schema
uzorak u originalnom PSD3 na block offsetu `0x1000`, čuva decoded binary,
logical schema, physical table, member groups, scalar profile i checksumove u
`out/orion_graph_schema_sample/`. Class instance handle allocator je: `0` je
external/null sentinel, zatim svi `kind=1` redovi dobijaju uzastopne handle-e u
schema redosledu; structure/array composite-i ih ne troše. Time se tačno dobiju
originalni opsezi `Clothoid 413..992`, `Edge 993..1572` i `Node 1573..1955`.
Svih 538 nenultih `From` i 556 nenultih `To` vrednosti pada u Node opseg, bez
odstupanja; 42/24 nule su sentinel-i.

`orion_object_writer.py --edges` generiše i zaseban
`graph_references.decoded.bin`, ali sada i kompletan
`integrated_graph.decoded.bin`. Naknadna fizička analiza originalnog graph
chunka ispravila je ranije grupisanje: `EdgeRoadElement.Attributes` je
implicitna 1:1 struktura bez serialized dela. Sledećih 383 vrednosti su tačna
permutacija kompletnog PointGeometry opsega `30..412` i pripadaju direktnom
`NodeRoadElement.PointGeometry` članu. Narednih 383 četvorobitnih vrednosti su
`Vias` cardinality (zbir 1.094), sledećih 1.094 `uint16` vrednosti su Edge
handle-i, a treći deo je optional/default. Writer ovo reprodukuje kao
PointGeometry `1..100`, Edge `101..200`, Node `201..300`, direktne `From/To`
reference i 76 lokalnih `Vias` incidencija. Integrisani binary ima 2.198 B i
svih 12 schema/table/value/range/incidence self-checkova prolazi. Puni originalni
PSD3 corpus je zatim ponovo prošao svih 42.066 byte-identical schema, tabela,
payload i decoded-chunk roundtrip provera. Taj topology chunk ostaje zaseban
kontrolni artefakt; objedinjeni rezultat je opisan ispod.

`tools/orion_centerline_writer.py` je autonomni izvršni dokaz za taj zasebni
centerline chunk. Svaki source pravolinijski segment zapisuje kao poseban
`ClothoidCenterlineGeometryPart` sa dve `PointLld` pozicije i jednakim u16
full-circle smerom na oba kraja; zato ne izmišlja tangent continuity na uglu.
Nad 100 edge-ova dobija 824 part-a, 1.648 PointLld redova i binary od 17.255 B.
`EdgeRoadElement.CenterlineGeometry` je direktan globalni handle u Clothoid
opseg i svih deset self-checkova prolazi. Fizički Direction tip i opseg su
originalni; konačna interpretacija ugla na uređaju ostaje device-validacija.

Spajanje je završeno u `tools/orion_merged_graph_writer.py`. Skripta zahteva
isti edge ID i isti redosled u graph i clothoid source-u, zatim gradi jedan
globalni class handle prostor. `tools/orion_property_layout_profile.py` je
zatim dokazao prvi property-container sloj na originalu: 580 Attributes
cardinality vrednosti razvija se u 586 PropertyD1 lista; njihove cardinality
vrednosti 3–4 daju tačno 1.760 handle-a, svi u Adas/AudiUrban/SpeedLimit/Urban
Property opsezima. Svih sedam layout provera prolazi.
`tools/orion_property_corpus_profile.py` proširuje dokaz na ceo originalni
ATLAS: 43.402 bloka, 42.081 decoded chunk, 8.081 graph/property chunk,
1.445.496 edge-eva, 1.511.928 lista i 4.801.622 klasifikovana handle-a. U
1.511.916 lista redosled je Adas→Urban→AudiUrban; samo 12 specijalnih lista ima
SpeedLimit→SpeedLimitSign. Merged writer sada za svaki edge emituje ta tri
obavezna handle-a: Adas i AudiUrban imaju po jedan nulti red, a Urban dva reda
`0/1` i bira ih iz firmware-potvrđenog MIB signala. Naknadni scalar dokaz nad svih 4.333 baseline-only
chunkova nema nijedan neuspeh: Adas je u svih 283.228 referenci nula;
Urban reference su 124.701×0 i 158.527×1, AudiUrban 126.965×0 i 156.263×1.
Egzaktni trojci su `0+0+0=124.701`, `0+1+0=2.264` i
`0+1+1=156.263`, pa je AudiUrban strogi podskup Urban-a u ovom
baseline-only skupu.

Obični Urban je sada zatvoren: `FUN_002f0484` radi OR bit-a `0x20` iz
`geometry_parts[].secondary_flags`, upisuje ga na decode output `+0x168`, a
caller `FUN_002f7c74` prosleđuje `edge_object+4`, što daje edge field `+0x16c`.
`FUN_013e5be8` direktno čita taj bajt za Urban Entry/Exit. Puni MIB profil ima
448.174 urban edge-a od 838.433. Susedni bitovi 4/6 ne zadovoljavaju originalni
AudiUrban-subset ugovor i nisu preimenovani. Dokaz se reprodukuje skriptom
`tools/run_basic_urban_semantics_re.py`; artefakti su u
`out/firmware_re/basic_urban_semantics/`.

Kanonski sample daje binary od 19.849 B: Adas `1`, AudiUrban `2`, Urban `3..4`,
PointGeometry `5..104`, Clothoid `105..204`, Edge `205..304`, Node `305..404`,
824 centerline part-a, 1.648 PointLld redova, 300 property i 76 Vias referenci.
Svih 21 self-checkova i checksumovi prolaze. Za zatvaranje stavke 2 ostaju
AudiUrban mapiranje i opcione speed/lane/restriction klase, pa ATLAS catalog/container.

`tools/run_psd15_profile_re.py` reprodukuje zaseban dokaz nad
`libATFPSDAdapter15.so`. `FUN_00036050` prolazi 46 tipizovanih profile
konvertera. Nedostajući debuglink je
`libATFPSDAdapter15.so-20160718160238.sym`, CRC `0x6f528a2a`; zato internal
PNAV attribute ID, vtable offset i javni ADASIS profile ID ne spajati na silu.
Artefakti su u `out/firmware_re/psd15_profiles/`.

Mrežna konfiguracija nije menjana: nisu dirani Wi-Fi/Ethernet interfejsi, DNS,
route tabela, DHCP niti reconnect. Internet je korišćen samo read-only za
javnu ADASIS v2 specifikaciju; sva obrada firmware-a i mapa ostala je lokalna.

Checkpoint 2026-09-02: full Property corpus profil, tri obavezne Property
klase/handle-i, firmware-backed Urban 0/1 writer, 113/113 testova, full-corpus
scalar/MIB prolazi i checksumovi su završeni. Sledeće dokazati samo AudiUrban
source mapiranje i opcione Property klase. Catalog/container stavka 3 još nije
pokrenuta.

## Reprodukcija završenog checkpoint-a

Puni testovi:

```bash
cd "<repo>"
python3 -m unittest discover -s tests -v
```

Puni suite posle Urban writer sloja prolazi **113/113** (`OK`), a
novi merged suite prolazi 2/2. Pri nastavku pustiti punu
discovery komandu. Suite uključuje
21/21 road-attribute unit testova, graph schema v7, full-corpus type-3
time-condition, geometry tag-2/tag-16 i kompletne AdvancedRouting/ADAS
cluster integracije, plus Orion catalog/column parser test.

Urban firmware dokaz bez mreže:

```bash
python3 tools/run_basic_urban_semantics_re.py \
  --output out/firmware_re/basic_urban_semantics
```

### AudiUrban korigovani checkpoint — 2026-09-03

Ne preimenovati secondary bit 6 u AudiUrban bez dodatnog dokaza. Trenutno je
dokazano samo sledeće:

- `FUN_002f0484`: OR `geometry_parts[].secondary_flags & 0x40`, rezultat na
  decode output `+0x1e9`;
- `FUN_013bcc28` predaje fizički cached-edge `+4` kao decode-output bazu, pa
  je kandidat u stvarnom objektu na `+0x1ed`;
- `FUN_010eec88` i `FUN_010f2b68` jesu kopije `decode_output+0x1e9` u
  `+0x281`, ali su string/call tragom identifikovane kao
  `OnBGeoPOIService::Start/UpdateResults`, ne kao route-edge consumer;
- puni sken 26.095 funkcija za `+0x281/+0x285` nema semantičkog čitaoca u
  GeoPOI objektu;
- egzaktni četvoroprocesni sken 44.531 funkcije za `+0x1e9/+0x1ed` u
  relevantnom navigation delu nalazi decoder, zero-init/copy puteve i GeoPOI
  bulk kopiju, ali ne i AudiUrban naziv ili consumer;
- primarni cached-edge vtable `0x01710798` ima samo dve destruktorske stavke;
  naredni slotovi pripadaju susednim malim tabelama i ne daju field getter;
- sirovi bit 6 pada na subset proveri `AudiUrban => Urban`, pa ne može sam
  biti writer source.

Za brze pune decompiler skenove koristi `tools/run_ghidra_sharded_grep.py`.
On pravi četiri privremene clone kopije Ghidra projekta zato što čak i
`-readOnly` headless proces zaključava projekat, pokreće šardove paralelno,
prikazuje napredak i spaja izlaze sa manifestom. Poslednji uspešan poziv:

```bash
python3 tools/run_ghidra_sharded_grep.py \
  --output out/firmware_re/basic_road_attributes_urban_probe/audiurban_route_edge_consumers.c.txt \
  --start 00800000 --end 01450000 --jobs 4 \
  --needle='+ 0x281' --needle='+ 0x285'
```

Ne nastavljati više od GeoPOI `+0x281`: taj trag je zatvoren kao nesemantička
bulk kopija. Sledeći smislen put je pratiti ceo cached-edge kroz kopije i
interfejse ili prostorno upariti MIB puteve sa originalnim 3G+ putevima, pa
izvesti kompletnu formulu i tek onda pokrenuti puni MIB subset profil.
Potpisan rezultat ove faze je u
`out/firmware_re/audiurban_candidate_phase/`.

Prostorno uparivanje je započeto i radi. `tools/orion_graph_spatial_probe.py`
čita originalne signed `PointLlh` koordinate kao `degree × 10^7`, bira bbox,
ima `--start-offset` resume i `--save-decoded`. Dokazano je da je Balkan u
`PSD/..._1.0.ATLAS`, ne u ranije profilisanom `PSD3/..._1.2.ATLAS`. Checkpoint
`out/orion_graph_spatial_probe_serbia_02/` sadrži osam originalnih decoded
graph chunkova iz Crne Gore (`18.40–18.44E`, `42.45–42.82N`) i njihove šeme;
sve šeme imaju `AudiUrbanProperty` (4–24 reda), Urban, edge/node i PointLlh.
Svi checksumovi prolaze. `tools/orion_edge_property_decode.py` je zatim
rekonstruisao `Attributes.Parts -> PropertyD1.Values` za svih 1.593 edge-a i
1.795 referenciranih lista. Čuva per-part trojke i efektivni edge OR; nijedan
edge nema nedostajuću baseline trojku. Opcione Property šeme daju 72 efektivna
edge-a sa `AudiUrban=1, Urban=0`, zato subset tvrdnja ostaje ograničena na
baseline-only corpus i ne sme služiti kao globalni filter. Potpisani izlaz je
`out/orion_edge_properties_montenegro/`, a svih 113 testova prolazi. Nastavak:
dekodirati From/To/centerline za iste edge redove i prostorno ih upariti sa MIB
edge-ovima.

Endpoint/topology deo tog nastavka je završen. Nova autonomna skripta
`tools/orion_edge_geometry_decode.py` ponovo dekodira originalne code-1 kolone,
proverava class-handle opsege i za svih 1.593 edge-a razrešava `From/To` preko
Node i PointGeometry redova do `PointLlh` koordinata. Property JSONL je spojen
strogo 1:1. Dobijeno je 1.260 node/point redova, 152 nulta endpoint sentinela
na granicama chunkova i 1.593/1.593 validnih `ClothoidCenterlineGeometry`
referenci. Izlaz i checksumovi su u `out/orion_edge_source_montenegro/`; suite
je 113/113 `OK`. `CenterlineGeometry.Parts` i pripadajući `PointLld` redovi
namerno još nisu interpretirani. Sledeća precizna tačka je njihov lossless
decode i tek zatim prostorni join sa MIB polilinijama.

To je sada urađeno za prošireni unutrašnji uzorak. Resume sken od
`0x7a7d21f0` sačuvao je 64 originalna chunka u
`out/orion_graph_spatial_probe_montenegro_04/`. Property/topology/centerline
pipeline je dao 21.570 edge-a, 21.642 centerline part-a i 110.965 lossless
PointLld redova. `tools/mib_graph_spatial_extract.py` je sa `--jobs 8`
pregledao svih 838.433 MIB edge-a i izdvojio 64.274 bbox kandidata.

Strogi 1:1 matcher potvrđuje da se segmentacija generacija znatno razlikuje.
Novi `tools/orion_mib_corridor_match.py` zato radi 1:N coverage proveru bez
spuštanja praga i nalazi 148 high + 643 medium parova. Ti parovi odbacuju
secondary bit 6 kao samostalnu AudiUrban formulu: u high grupi za originalni
AudiUrban=1 dobijeno je bit6=0 u 97 i bit6=1 u 14 slučajeva. Ovo je korelacioni,
ne object-identity dokaz. Nastavak je topološki chain matcher koji kombinuje
geometriju, susedstvo, smer i stabilne atribute; tek njegov jednoznačan subset
sme da se koristi za izvođenje AudiUrban formule.
`tools/audiurban_spatial_feature_profile.py` je na svih 148 high parova
profilisao bitove 0–7. Najbolji direktni bit je 5 sa samo 56,46% slaganja;
bit 6 ima 31,69%. Dakle, nijedan pojedinačni secondary bit nije AudiUrban.

`tools/orion_mib_topology_chain.py` zatim proverava stvarnu povezanost po MIB
from/to node ID-jevima i ponovo meri spojenu poliliniju. Od 791 corridor reda
dobijeno je 6 high + 20 medium čistih lanaca, dužine 1–5 MIB edge-ova. Ostali
nisu proglašeni identičnim. Naredna precizna granica je bounded graph search
koji sme dodati samo kratke nedostajuće MIB veze unutar originalnog
geometrijskog koridora.

Bounded varijanta je završena u `tools/orion_mib_bounded_graph_match.py`.
Pretražuje do 12 hopova samo kroz MIB edge-ove unutar originalnog koridora i
ponovo ocenjuje celu spojenu geometriju. Koridor 80 m daje 8 high + 50 medium
putanja, do 6 edge-ova. Kontrola na 120 m daje identičnih 8+50 i samo više low
rezultata, zato prag ne širiti. Među 58 prihvaćenih putanja originalni
AudiUrban=1 prati MIB bit6=0 u 35/36 slučajeva. Sledeće nije još širi spatial
search, već direction/road-class/name atributski score i novi originalni
uzorak sa više nepromenjenih puteva.

`mib_graph_spatial_extract.py` sada emituje travel direction, automotive mask,
speed tagove i lane/passing prisustvo. Profil na 58 prihvaćenih putanja je u
`out/orion_mib_stable_attributes_montenegro_04/`: lane presence 96,55% je
dominantno negativan signal bez pozitivnih potvrda, passing 87,93%, speed
56,90%; automotive bit 8 prema AudiUrban ima samo 70,69%. Ništa od toga još
ne koristiti kao identity uslov. Nastavak: dekodirati vrednosti originalnih
SpeedLimit/NumberOfLanes/PassingRestriction klasa i tek njih uključiti.

Originalne opcione Property vrednosti su sada lossless dekodirane u
`out/orion_edge_properties_montenegro_04/`. `orion_edge_property_decode.py`
više ne koristi poseban offset po klasi: gradi ceo Property member potpis,
sidri ga na proverene Adas/AudiUrban/Urban kolone, prihvata fizički uži unsigned
tip samo kada staje u logički tip i odbija nejednoznačno poravnanje. Obrađuje i
tri `kind-3` dictionary kolone preko njihovih anonimnih row-index kolona.
`SpeedLimit.Time` je implicitno row-aligned sa `TimeDomain`, pa su njegova dva
raw dela sačuvana po objektu. Prolaz je 64/64 chunk-a, 21.570 edge-a, 748
SpeedLimit, 390 NumberOfLanes, 263 PassingRestriction i 54 SpeedBumps reda;
sve provere i checksumovi prolaze. Ne izmišljati enum značenja: trenutno su
stabilni raw brojevi plus descriptor/reference provenance. Sledeći posao je
poređenje punih vrednosti sa MIB atributima na 58 bounded putanja, pa ponovno
ocenjivanje matcher-a samo ako signal bude dovoljno jak.

Value-level profil je sada u
`out/orion_mib_property_values_montenegro_04/`. MIB compact corpus je ponovo
izvučen kroz 8 procesa preko svih 838.433 edge-a i sada čuva simple/extended
speed, lane endpoint brojeve i passing direction/detail zapise. Od 58 bounded
putanja samo jedna ima speed na obe strane i skupovi nisu jednaki; lane i
passing nemaju nijedan both-present par. U geometry-high grupi 3/8 imaju speed
samo na jednoj strani. Zato ništa od ovoga još ne dodavati u score niti tvrditi
da su geometrijski parovi semantički isti. Sledeći korak je širi stabilni uzorak
sa topology/name/direction identitetom koji može razlikovati promenu godišta od
pogrešnog prostornog uparivanja.

Nastavak je automatizovan u `tools/run_orion_cross_version_corpus.py`. Jedna
komanda od resume offseta sada pokreće kompletan lokalni pipeline, prosleđuje
live output i koristi 8 procesa u prostornim fazama. Corpus 05: 64 chunk-a,
20.369 edge-a, 90.409 PointLld, bounded 1 high + 6 medium. Corpus 06: 128
chunkova, 31.740 edge-a, 309.762 PointLld, bounded 1 high + 8 medium. Ukupno sa
corpusom 04: 256 chunkova, 73.679 originalnih edge-a, 511.136 PointLld i 74
accepted bounded putanje (10 high + 64 medium). Sledeći resume offset je
`0x7acec040`.

`tools/orion_mib_direction_profile.py` ne veruje redosledu `edge_ids`, već
isprobava oba reda i oba početna smera, zahteva tačno node-povezan lanac i bira
po originalnom From/centerline početku. Zbirni MIB modovi su 66 both, 6 closed,
2 reverse. Orientation podaci su retki i nekonzistentni za izvođenje enum
značenja; corpus 05/06 nisu dodali nijedan both-present atributski dokaz.
Direction/property još ne ubacivati u hard score. Sledeći jak discriminator
mora biti name/road-class ili ručno potvrđen isti put kroz oba godišta.

`tools/orion_item_identifier_profile.py` završava prvu identity proveru nad
sva tri corpusa. Fizički `Item.Identifiers` payload tačno pokriva class-ordered
`Item` potomke sa po 8 bajtova: 134.581 redova ukupno i 73.679 edge redova.
Dobijeno je 130.929 jedinstvenih `u64` vrednosti; 3.533 vrednosti se ponavljaju
između chunkova (3.652 dodatna reda), bez ponavljanja unutar jednog chunka.
Sve ponovljene vrednosti pripadaju edge klasama, ali svih 3.780 pairwise
geometrijskih poređenja je različito; 3.403 para samo dele kraj/prostor unutar
10 m. Zaključak: ovo nije stabilan jedinstveni edge/object identitet i ne
koristiti ga za join. Puni raw `u64`, `low_u32`, `high_u32`, duplicate grupe,
report i checksumovi su u `out/orion_item_identifiers_montenegro_04_06/`.
Mogući road-group/name-key smisao nije dokazan. Tačna tačka nastavka, tek posle
korisničkog pregleda, bila je dodavanje normalizovanih MIB imena/road-class u
kompaktni prostorni corpus i cross-tab tih atributa prema ponovljenim ključevima.

To je završeno. `mib_graph_spatial_extract.py` schema-v3 sada u 8 procesa
dekodira direct handle-2 logička imena, normalizuje base i transliteration
varijante i čuva lokalni endpoint node-record low nibble koji firmware vraća u
VA `0x0154faec`; external endpoint vrednost je namerno `null`. Puni prolaz:
838.433 skeniranih edge-a, 149.105 bbox edge-a, 67.068 sa imenima, 91.835
normalizovanih name referenci i 274.373 lokalna endpoint-class polja. Izlaz:
`out/mib_graph_spatial_montenegro_names_06/`.

`tools/orion_mib_name_identity_profile.py` koreliše svih 1.110 high/medium
corridor redova. Među 23 ponovljena `Item.Identifiers` para name odnos je 13
equal, 4 overlap, 6 missing i 0 disjoint; endpoint class je 18 equal, 4 overlap,
1 missing. Međutim, MIB edge skupovi su 10 equal i 13 overlap, bez disjoint
slučaja. Zato slaganje imena nije nezavisan dokaz name-key semantike: potvrđuje
cross-chunk lokalno grupisanje, ne jedinstveni edge identitet. Dokazni izlaz je
`out/orion_mib_name_identity_montenegro_04_06/`. Sledeća granica je nezavisan
uzorak ponovljenih ID-jeva čiji MIB edge skupovi ne dele isti segment ili
dekodiranje originalnog Orion name/road-class property sloja.

Ta granica je sada pomerena. `tools/orion_schema_name_inventory.py` je sa 8
radnika pregledao sve logičke šeme u PSD0/PSD1/PSD3. Ukupno 219.365 graph
`Map` šema nema road-name/road-class kolonu; PSD3 ima još 33.985 `VidTable`
šema. Parser sada podržava i direct-container CTY legacy šemu bez annotations;
CTY0 daje 213.041 `Map` šema za 3D `Building`/`Material`/`VertexArray`, ne road
nazive. Rezultati su u `out/orion_schema_name_inventory*`. GDB/GD2 i LIT/LI*
su zaseban legacy subsystem; nisu parsirani, a probna konkretna imena nisu
plaintext pronađena.

Važan pozitivan dokaz je u
`out/orion_vidtable_identifier_profile_montenegro_04_06/`.
`tools/orion_vidtable_identifier_profile.py` je nad kompletnim PSD3 pregledao
svih 33.985 VidTable tabela i 94.974.728 fizičkih AtlasIds dictionary vrednosti
kao pune `u64`. Egzaktno 65.841 od 130.929 jedinstvenih `Item.Identifiers`
vrednosti postoji i u `VidTable.AtlasIds`; to je 69.253 Item reda, svi
`EdgeRoadElement`, i 76.457 VidTable pojavljivanja. Dakle zajednički ID domen
je dokazan bez oslanjanja na low-u32 slučajnosti. Ovo ne vraća raniju tvrdnju
da je vrednost jedinstveni edge ID: duplikati i dalje grupišu više segmenata.

TAČNA TAČKA NASTAVKA, tek posle korisničkog `ajde`: dekodirati VidTable
optional/indirect row-to-dictionary mapiranje, vezati svaki AtlasId sa njegovim
`XacVectorOffsets`, zatim protumačiti ciljni XAC zapis. Tek taj dokaz određuje
da li sledeći hop ide direktno u XAC payload ili dalje u GDB/LIT; ne nagađati
unapred. Pokretati kao lokalnu skriptu sa 8 radnika i prenositi live output.

Row-mapping deo je sada završen. Novi
`tools/orion_vidtable_row_mapping.py` podržava direct AtlasIds i tag-3
dictionary + anonimnu index kolonu. Puni PSD3 prolaz: 33.985 tabela, od toga
13.871 direct i 20.114 indirect; ekspandirano je 170.571.814 poravnatih
`AtlasId → XacVectorOffset` redova. Sve count/dictionary/index/alignment i
per-table offset-uniqueness provere prolaze. Za poznatih 65.841 zajedničkih
ID-eva sačuvano je 299.486 konkretnih redova u
`out/orion_vidtable_row_mapping_montenegro_04_06/`; `tables.jsonl` čuva profil
svih tabela, a `selected_item_rows.jsonl` samo relevantne redove.

Mali korak 2 je završen skriptom `tools/orion_xac_vector_bind.py`. Ona parsira
FLDB direktorijum, ali `VEKTORBLOCK` traži po kompletnom fizičkom DB prostoru,
jer 31 vezani blok leži u unowned/continuation zonama. Tri sharda sadrže
26.684 + 18.294 + 2.198 = 47.176 fizičkih markera. Svih 33.985 VidTable
row-countova postoji kao uređen podniz i svaki izabrani par ima isti count;
33.923 pozicije su prisiljene forward/backward order dokazom. Preostalih 62
tabela ima 147 mogućih fizičkih kandidata zbog ponovljenog counta; sačuvani su
u `out/orion_xac_vector_binding/ambiguous_binding_candidates.jsonl`, bez
preuranjenog izbora. Ostali artefakti su `bindings.jsonl`,
`unmatched_xac_vectors.jsonl`, FLDB direktorijum, report i checksumovi.

Svaki izabrani `XacVectorOffset` maksimum je manji od konzervativne fizičke
granice narednog markera/kraja vlasničkog entry-ja. To dokazuje da je namespace
lokalan pridruženom vector blocku. Ne koristiti BE u32 na markeru `+16` kao
hard kraj: 3.500 tabela ga prelazi (najviše 248 bajtova), pa unutrašnja baza i
extent formula još nisu protumačeni.

Ta faza je završena u `tools/orion_xac_vector_offset_resolve.py`, uz firmware
dokaz u `out/firmware_re/orion_xac_bridge/navcore_xac_iterator_strings.c.txt`.
NavCore formula je:

- version <=4/direct: `target = marker + XacVectorOffset`;
- version >4 i BE16 `+0x72 == 1`: index tabela je na BE32 `+0x6c`, njen count
  na BE16 `+0x70`, offset mora biti paran, a target je
  `marker + 2*BE16(index_table + XacVectorOffset)`.

Puni 8-worker prolaz ponovo je dekodirao i proverio 170.571.814 vrednosti.
Rezultat: 9.648 direct + 24.337 indexed tabela; svi targeti su u fizičkoj
granici i svi imaju firmware vector potpis `(first_byte & 0xc0) == 0xc0`.
Struktura je razrešila 41 ranije ambiguous tabele. Među 33.929 jednoznačnih
named-XAC veza svaka je `_2.xac` i nijedna `_1.xac`; taj dokazani invariant i
globalni order razrešavaju preostalih 21. Konačno: 33.985 unique, 0 unresolved.

Izlaz `out/orion_xac_vector_offset_resolution/` sadrži `resolved_tables.jsonl`,
prazan `unresolved_candidates.jsonl`, report/checksumove i 299.486 konkretnih
`selected_item_targets.jsonl` redova sa Atlas ID-em, DB/owner fajlom,
markerom, apsolutnim/relativnim targetom i 16-bajtnim prefixom.

### XAC vector-record / name-reference checkpoint — 2026-09-03

Prethodna tačka nastavka je izvršena. Pipeline `tools/orion_xac_pipeline.json`
je završio sa stanjem `out/orion_xac_pipeline_state_v3.json`; svih deset
stupnjeva ima exit code 0. Novi parseri obavezno dobijaju dva odvojena ulaza:

- XAC `*.db` mmap za record bajtove;
- `$NAVCORE_ELF` za
  firmware descriptor tabelu.

Ne vratiti staru probnu varijantu koja descriptor uzima iz XAC fajla. Ona je
davala pogrešne statičke deskriptore; zato `structural_cursor` nije kraj
recorda već samo cursor do optional name-reference nastavka.

Potvrđena gramatika iz `get_names_of_vector` je:

- validan record ima `(b0 & 0xc0) == 0xc0`;
- key je `((b2 & 7) << 8) | b3`;
- kada je `b2 & 8`, header/key se nasleđuje sa `(target + 4) - (key * 2 + 2)`;
- key bira descriptor na `0x085b4fe8 + 0x1c + key * 4`; descriptor flagovi
  upravljaju opcionim cursor pomacima i name granom.

`tools/orion_xac_vector_record_layout.py` je u 8 procesa obradio svih 299.486
targeta u 96 DB grupa bez greške. `tools/orion_xac_vector_name_refs.py` je
na recordima sa name flagom pročitao packed 14-bitne ID-jeve (continuation bit
iz prvog bajta): 25.110 recorda, 44.722 reference i 8.877 jedinstvenih ID-jeva,
bez invalid/unterminated liste. Izlazi su
`out/orion_xac_vector_record_layout/report.json` i
`out/orion_xac_vector_name_refs/report.json`.

Dokaz za sledeći hop je već izdvojen: `FUN_082538e4` razrešava name ID,
`FUN_082539f0` vraća language ID, a `FUN_08253ba0` dekompresuje/cache-ira
name blok; dekompajl je u
`out/firmware_re/orion_xac_bridge/navcore_xac_name_loader_xrefs.c.txt`.
`xac_name` text resource još nije lociran/inicijalizovan, pa ove ID-jeve ne
pretvarati u stringove niti im dodeljivati road-class značenje.

**Sledeća tačna tačka nastavka:** pronaći fizički `xac_name` resource kroz
FLDB/XAC direktorijum i rekonstruisati object loader dovoljno da se nad realnim
name ID-jem dobiju text, language i name type. Rad ostaje read-only; ne skakati
na GDB/LIT bez veze iz ovog loadera.

Poslednja potvrđena puna lokalna provera prolazi 132/132 testova (`OK`); checksumovi
VidTable row-mapping i XAC vector-binding artefakata su generisani i potvrđeni.

Standardni prolaz namerno preskače veliki renderer. Opcioni `--deep` dodaje
široki katalog/string i susedni-field scan.

Prvi autonomni object writer:

```bash
python3 tools/orion_object_writer.py \
  out/basic_graph_export/nodes.jsonl \
  --edges out/basic_graph_export/edges.jsonl \
  --output out/orion_point_llh_writer \
  --limit 100 --edge-limit 100
```

Izlaz: `point_llh.decoded.bin`, lossless `point_llh.rows.jsonl`,
`graph_references.decoded.bin`, `graph_references.rows.jsonl`,
`integrated_graph.decoded.bin`, `integrated_graph.nodes.jsonl`,
`integrated_graph.edges.jsonl`, `manifest.json` i `CHECKSUMS.sha256`.
`--limit 0 --edge-limit 0` obrađuje ceo dati JSONL;
trenutni canonical `nodes.jsonl` je sample od 100 redova.

Autonomni centerline writer:

```bash
python3 tools/orion_centerline_writer.py \
  out/orion_clothoid_source/clothoid_edges.jsonl \
  --output out/orion_centerline_writer \
  --limit 100
```

Izlaz: `centerline_graph.decoded.bin`, `centerline_graph.edges.jsonl`,
`manifest.json` i `CHECKSUMS.sha256`. `--limit 0` obrađuje ceo dati JSONL.

Jedinstveni topology + centerline graph:

```bash
python3 tools/orion_merged_graph_writer.py \
  out/basic_graph_export/nodes.jsonl \
  --edges out/basic_graph_export/edges.jsonl \
  --clothoids out/orion_clothoid_source/clothoid_edges.jsonl \
  --output out/orion_merged_graph_writer \
  --node-limit 100 --edge-limit 100
```

Izlaz: `merged_graph.decoded.bin`, `merged_graph.nodes.jsonl`,
`merged_graph.edges.jsonl`, `manifest.json` i `CHECKSUMS.sha256`.

Property layout dokaz:

```bash
python3 tools/orion_property_layout_profile.py \
  out/orion_graph_schema_sample/sample_00.schema.json \
  out/orion_graph_schema_sample/sample_00.decoded.bin \
  --output out/orion_property_layout_profile
```

Puni Property corpus dokaz:

```bash
python3 tools/orion_property_corpus_profile.py \
  $MMI3G_PKGDB/PSD3/APN221EU22093P1664a.5_1.2.ATLAS \
  --output out/orion_property_corpus_profile --quiet
```

Autonomni road-attribute stage:

```bash
python3 tools/run_basic_road_attributes_stage.py \
  $MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf \
  --output out/basic_road_attributes_stage \
  --sample-limit 100 \
  --transliterate-identifier 30 \
  --transliterate-identifier 33 \
  --transliterate-identifier 48
```

Autonomni name stage:

```bash
python3 tools/run_basic_name_stage.py \
  $MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf \
  --output out/basic_name_stage_latin \
  --sample-limit 100 \
  --transliterate-identifier 30 \
  --transliterate-identifier 33 \
  --transliterate-identifier 48
```

Regionalni ID cross-check direktno iz arhiva:

```bash
python3 tools/run_basic_identifier_crosscheck.py \
  $MIB_ARCHIVE \
  --output out/basic_identifier_crosscheck \
  --sample-limit 20
```

Pre-writer edge join i clothoid provera:

```bash
python3 tools/pre_writer_layers_export.py \
  --basic $MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf \
  --advanced-routing $MIB_MAP_ROOT/SerbiaMontenegroKosovo_AdvancedRouting.psf \
  --adas $MIB_MAP_ROOT/SerbiaMontenegroKosovo_ADAS.psf \
  --output out/pre_writer_layers_source

python3 tools/orion_clothoid_export.py \
  $MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf \
  --output out/orion_clothoid_source --sample-limit 100

python3 tools/run_pre_writer_layers_re.py \
  --output out/firmware_re/pre_writer_layers
```

Poslednja checksum provera je prošla za:

- `out/basic_world_country_languages/`;
- `out/basic_handle2_name_profile/`;
- `out/basic_graph_export/`;
- `out/basic_graph_export_latin/`;
- `out/basic_name_stage_latin/`;
- `out/basic_identifier_crosscheck/`;
- `out/firmware_re/basic_handle2/`;
- `out/firmware_re/basic_road_attributes/`;
- `out/basic_road_attributes_profile/`;
- `out/basic_road_attributes_stage/`;
- `out/pre_writer_layers_profile/`;
- `out/pre_writer_layers_source/`;
- `out/firmware_re/pre_writer_layers/`;
- `out/orion_clothoid_source/`.
- `out/orion_point_llh_writer/`.
- `out/orion_graph_schema_sample/`.

## Container sloj — checkpoint 2026-09-03 (Claude)

Stavka 3 je otvorena i vecim delom zatvorena; specifikacija je u
`docs/ATLAS_CONTAINER.md`, status u `docs/IMPLEMENTATION_STATUS.md`.
Kljucne cinjenice koje ne smeju da se izgube:

- indeks postoji SAMO u delu 0 baze (`REVISION` + `INDEX` blokovi odmah
  iza `HEADER`-a); PSD3 je deo 2 i zato ga raniji rad nije video;
- LZMA rečnik je 1 MiB; 64 KiB je davao 835 laznih "korumpiranih" blokova;
- terminator je poslednjih 16 B bloka; `+0x20` je codec (1/2/3);
- `K = C<<8 | B_hi` je prostorni kljuc binarnog stabla, `A` nivo,
  `K_base = 0x1018000000` za PSD;
- separator na svim nivoima indeksa = zaglavlje prvog bloka sledeceg deteta.

Alati: `orion_atlas_header_decode`, `orion_block_grammar_verify`,
`orion_container_header_decode`, `orion_index_decode`,
`orion_index_root_decode`, `orion_block_writer`, `orion_lzma_failure_probe`,
`orion_block_key_spatial_probe`, `orion_tile_grid_probe`,
`orion_tile_formula_verify`, `orion_nonkey_block_profile`,
`run_container_pipeline` + `orion_container_pipeline.json`.

Krajnji cilj korisnika: MIB mapa prepakovana u 3G+ format, instalirana u
njegov auto kao obican map update; posle toga svi alati i postupak (bez
mapa) idu na GitHub za DIY.

## Trenutna upotrebljivost za 3G Plus

Source je spreman za razvoj i testiranje `NodeRoadElement`,
`EdgeRoadElement`, `From`/`To`, centerline, lokalizovanog name adaptera i
osnovnih direction/speed/lane/passing property adaptera. Clothoid source i
lossless AdvancedRouting/ADAS edge join su takođe spremni. Nove fizičke code-1
`PointLlh` i direktne `EdgeRoadElement.From/To` kolone su generisane i
samoproverene. Nije kompletna rutabilna `.ATLAS` baza dok ne budu završene
složene object reference, integrisani graph chunk, container/indeksi i
otvoreni road/AdvancedRouting/ADAS semantički delovi.

## MIB → 3G+ konverzija — kompletna (2026-09-03)

Ceo lanac je prošao **pun Serbia/Montenegro/Kosovo dataset**, ne uzorak.
Manifest sa checksumovima: `out/conversion_manifest/manifest.json`.

| Korak | Izlaz | Zapisa/veličina |
|---|---|---|
| 1. MIB izvor | `SerbiaMontenegroKosovo_Basic.psf` | 47,26 MB |
| 2. graf (čvorovi/ivice) | `out/basic_graph_export_full/` | 717.730 / 838.433 |
| 3. clothoid centerline | `out/orion_clothoid_source_full/` | 838.433 |
| 4. prostorne ćelije | `out/orion_cell_partition_full/` | 3.877 |
| 5. CONTAINER blokovi | `out/orion_cell_chunks_full/` | 3.915, 32,2 MB |
| 6. **GOTOV ATLAS + .conf** | `out/orion_atlas_build_full/pkg/` | `SRB.5_1.0.ATLAS` 32,3 MB |

Generisani ATLAS prolazi sve verifikatore (grammar 3920/3920, index 0
grešaka, roundtrip 3915/3915 bajt-identično, formula `exact`, spatial ključevi
strogo rastući). Writer je dokazan i roundtrip-om nad originalnom PSD bazom
(5,04 GB, bajt-identična rekonstrukcija HEADER/REVISION/INDEX).

Strukturno kompletna 3G+ ATLAS baza napravljena iz novijih MIB podataka.
Prihvatanje na uređaju zahteva izdavačev potpis/FSC (vidi
`docs/FW_PROTECTION_MODEL.md`).
