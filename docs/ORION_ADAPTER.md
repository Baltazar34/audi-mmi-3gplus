# PSF60 → Orion/ATLAS adapter: ugovor i trenutno stanje

## Kratak odgovor

Pre-writer source je sada upotrebljiv kao **ulazni routing graph sa imenima,
osnovnim road atributima, lossless AdvancedRouting/ADAS recordima i clothoid
source-om** za implementaciju MMI 3G Plus adaptera. Nije još dovoljan za
generisanje kompletne, rutabilne `.ATLAS` baze: prvi fizički `PointLlh`
code-1 writer i direktne `From/To` globalne reference rade, ali složene object
reference, AdvancedRouting/ADAS unutrašnja
semantika i ATLAS container/indeksi još nisu završeni.

Originalni 3G Plus XAC enrichment sada ima zatvoren address/record-reference
most, ali ne i tekstualni name sloj: 299.486 relevantnih `AtlasId` redova
jednoznačno je vezano do XAC recorda; 25.110 recorda nosi 44.722 name reference
prema 8.877 ID-jeva. To je dobar, proverljiv ulaz za budući 3G+ name adapter,
ali nije dozvoljeno prikazivati te ID-jeve kao nazive dok se ne rekonstruiše
`xac_name` loader/decompressor.

Automatski dokaz je `tools/basic_graph_export.py`. Nad Serbia uzorkom daje:

- 717.730 čvorova;
- 838.433 ivice;
- 903.487 uzastopnih geometry delova;
- 3.895.681 tačku spojenih centerline-a;
- 1.676.864 adjacency reference, bez ijednog razrešivog neslaganja;
- 65.054 spoja geometry delova, svi identični na granici;
- nula coordinate-table endpoint grešaka.
- 182.377 jedinstvenih handle-2 recorda i 271.823 tekstualna kandidata,
  dekodiranih bez greške;
- 549.784 edge-a sa 995.298 name-candidate referenci i 938.434 fonetske
  reference;
- 151.818 logičkih imena i 120.005 base→transliteration parova, uz
  `30=Bosnian`, `31=Albanian`, `33=Serbian`, `48=Montenegrin`.
- 838.433 potvrđena static-direction rezultata;
- 156.406 simple-speed zapisa na 117.458 edge-a;
- 61.618 extended-speed zapisa na 23.844 edge-a; direction, subtype, vrednost,
  subtype-7 condition parovi i source selector su lossless dekodirani;
- 1.632 `NUMBER_OF_LANES`, 50.617 simple i 9.942 extended passing zapisa;
- 15.614 `LANES` atributa sa 39.538 tipizovanih četvorobajtnih slogova;
  firmware-consumed polja i category maske su izvezene, javna enum imena ostaju
  otvorena; dokazan je i 13-bitni automotive mask.
- 868 dynamic topology direktorijuma sa 1.178 typed payloada, svih 3.324
  descriptor dynamic markera i 1.819 firmware-dekodiranih type-5 edge slogova.
- 308 type-3 time-condition selector slogova vezanih za edge i 56 deljenih
  condition objekata; direction/query grupa, timezone indeks i kalendarska/
  vremenska polja su dekodirani bez offset/key greške.
- 838.433 ADAS recorda vezanih 1:1 za Basic edge i 838.313 regularnih
  AdvancedRouting recorda; dodatnih sedam supra klastera ima 1.188 recorda.
- 3.895.681 source tačka prevedena je u 3.057.085 validnih specijalnih
  clothoid segmenata (`kappa=0`, `dkappa=0`), uz 163 zero-length kraka i
  maksimalnu endpoint grešku 0.0.

Četiri `explicit` endpoint-a su nezavisno kvantizovana i razlikuju se od
kanonske node koordinate za najviše 12 Mercator jedinica. Topološki node ID je
kanonski; originalna eksplicitna koordinata ostaje sačuvana u geometriji.

## Stabilni source ugovor

Komanda:

```bash
python3 tools/basic_graph_export.py Basic.psf \
  --output basic-graph --sample-limit 100
```

Skripta uvek čita i proverava ceo korpus. `--sample-limit` ograničava samo broj
upisanih NDJSON redova; vrednost `0` upisuje ceo graf.
Ponovljivi `--transliterate-identifier ID` aktivira dokazani firmware izbor
alternate oblika samo za zadate jezike; bez opcije se bira base. Ovo ne
odbacuje ostale jezike ili aliase iz `logical_names`.

`nodes.jsonl` sadrži:

- stabilni `node_id = cluster_id << 8 | local_index`;
- Mercator i WGS84 koordinatu;
- lokalne i eksterne adjacent edge ID-jeve;
- marker coordinate zapisa;
- još neimenovane node atribute kao raw provenance.

`edges.jsonl` sadrži:

- stabilni `edge_id`;
- logičke `from` i `to` node reference;
- kontinuirani `centerline_points` niz;
- originalne `geometry_parts` i njihove granice;
- `name_candidates` sa jezičkim identifier-om, sirovim fizičkim redosledom,
  vrednostima i fonetikom;
- `logical_names` sa odvojenim base/transliteration oblikom i eksplicitnim
  firmware-style `display_selection` rezultatom;
- `semantic_record` offset/flags/auxiliary provenance;
- `road_attributes.static_travel_direction`;
- simple-speed kandidate, node-A/node-B lane-count kandidate, simple/extended
  passing, extended-speed kandidate i field-level dekodirane `LANES` slogove sa
  firmware category maskom i raw provenance;
- `extended_automotive_attributes.base_mask` i dynamic marker;
- `extended_automotive_attributes.active_bit_indices` kao lossless 0..12
  decomposition; javna imena bitova ostaju `null` do direktnog API dokaza;
- `road_attributes.urban.value`, dokazano kao OR geometry-part secondary
  flag bit-a 5 (`0x20`) preko decoder VA `0x002f0484` i consumer VA
  `0x013e5be8`;
- `dynamic_topology_attributes` sa directory type provenance i, kada postoji,
  type-5 edge numeričkom override vrednošću i type-3 edge selector/condition
  provenance; type-5 javno ime/jedinica ostaju otvoreni, dok je condition
  kalendar dekodiran i čeka adapterov runtime timezone/query ulaz;
- originalni descriptor, tagged payload i extension sadržaj bez gubitka bajtova.

`report.json` čuva globalne brojeve i rezultate svih provera, a
`CHECKSUMS.sha256` štiti sva tri artefakta.

## Direktno mapiranje na Orion rečnik

| Orion koncept | PSF60 graph source |
|---|---|
| `NodeRoadElement` | jedan `nodes.jsonl` zapis |
| `EdgeRoadElement` | jedan `edges.jsonl` zapis |
| `From` | `edge.from.node_id` |
| `To` | `edge.to.node_id` |
| `CenterlineGeometry` | `edge.centerline_points` |
| `Parts` | `edge.geometry_parts[]` |
| `PointLld` | WGS84 tačke u centerline/parts |
| `NameCandidates` | `edge.name_candidates[]` |
| `Name` | `edge.name_candidates[].values[]` |
| `PhoneticName` | `edge.name_candidates[].phonetics[]` |
| logičko lokalizovano ime | `edge.logical_names[]` |
| prikazni oblik za zadati profil | `edge.logical_names[].display_selection` |
| dozvoljeni statički smer | `edge.road_attributes.static_travel_direction` |
| `UrbanProperty.Urban` | `edge.road_attributes.urban.value` |
| `SpeedLimitProperty` source | `edge.road_attributes.simple_speed_limit_candidates[]` |
| `NumberOfLanesProperty` source | `edge.road_attributes.number_of_lanes_candidates[]` |
| `PassingRestrictionProperty` source | simple/extended passing polja u `road_attributes` |
| `Lanes` source | `edge.road_attributes.lanes_candidates[]` |
| automotive raw source | `edge.road_attributes.extended_automotive_attributes` |
| dynamic topology source | `edge.road_attributes.dynamic_topology_attributes` |
| AdvancedRouting raw source | `out/pre_writer_layers_source/edge_layers.jsonl[].advanced_routing` |
| ADAS raw source | `out/pre_writer_layers_source/edge_layers.jsonl[].adas` |
| supra routing source | `out/pre_writer_layers_source/advanced_routing_supra.jsonl` |
| `ClothoidCenterlineGeometry` source | `out/orion_clothoid_source/clothoid_edges.jsonl` |

Ovo je konceptualni adapter sloj. Originalni PSD3 je sada potvrdio da se sve
prepoznate fizičke kolone mogu emitovati konzervativno kao codec 1,
native-width i sekvencijalni payload. Object flattening, reference i indeksi
ostaju zaseban writer sloj.

## Šta još blokira kompletan `.ATLAS`

1. Završiti jedinicu simple-speed vrednosti, time-dependent smer/speed,
   lane-record pod-enume i vehicle-class značenja automotive maske.
2. Prevesti AdvancedRouting record tagove u dokazanu manevar/restriction
   semantiku; strukturni i 1:1 source sloj je završen.
3. Prevesti interne ADAS profile/attribute ID-jeve u javna imena i jedinice;
   framing i edge povezivanje su završeni.
4. **Završeno za konzervativni writer:** svaki zero-curvature source segment
   postaje zaseban dvotačkasti clothoid part; endpoint-i su očuvani i tangent
   continuity između part-ova se eksplicitno ne tvrdi.
5. **Završeno:** logički composite/member opisi grupisani su sa svim fizičkim
   delovima; `kind 3` reference na skrivene članove povezane su lokalno.
6. **Drugi property korak otvoren:** generator novih code-1 kolona sada u jednom
   decoded chunku obuhvata `PointLlh`, `PointGeometry`, `PointLld`, clothoid
   part-ove, `EdgeRoadElement.CenterlineGeometry/From/To`, `NodeRoadElement` i
   `Vias` po originalnom globalnom class allocatoru. `Attributes.Parts`,
   trodelni `PropertyD1.Values` i tri obavezne Property podklase sada se
   serijalizuju sa konkretnim handle-ima. Urban ima dva reda `0/1` i bira se iz
   dokazanog MIB geometry flag-a; Adas nula je corpus-potvrđena, dok je samo
   AudiUrban nula konzervativni fallback. Slede AudiUrban semantika i opcione Property klase, pa container
   indeksi, apsolutni offseti i repack.

## Originalni 3G Plus PSD kao ciljna referenca

`tools/orion_psd_reference_profile.py` čita originalni `.ATLAS` read-only,
šeta blokove preko njihovih veličina, raspakuje raw LZMA1/zlib delove i izvlači
tagovani katalog i column deskriptore. Nad prvih 3.000 blokova `PSD3` iz izdanja
6.36.0 potvrđeno je:

- 3.011 uspešno raspakovanih delova i jedan neuspeh;
- 130 različitih imena i 238.395 pojavljivanja kataloga;
- svih 18 očekivanih ciljnih koncepata, uključujući graf, `From/Vias/To`,
  clothoid, brzine, trake, `ManoeuvrePart` i `AdasProperty`;
- 2.999 pojavljivanja glavnih graph/ADAS/manoeuvre objekata.

Naknadni puni prolaz je pokrio svih 43.402 blokova i ceo fajl. Strogo je
prepoznato svih 42.066 logičkih/fizičkih tabela; svih 649.210 codec bajtova ima
vrednost 1, a svih 42.066 payload-a se završava tačno i prolazi byte-identical
split→assemble proveru. `tools/orion_column_codec.py`
implementira provereni LSB-first reader, native-width type mapu, strogi code-1
layout i assembler. `tools/run_orion_column_codec_re.py` reprodukuje firmware
dokaz i ispravlja staru pretpostavku: code 3 nije prost width-prefixed niz već
kompozitni/rečnički codec koji rekurzivno poziva `CDecompression::create`.

Strogi logical-schema parser reprodukuje NavCore `parseDescriptions`: composite
kind, class base, row count, member name/type, annotation i composite reference.
Na prvih 3.000 blokova svih 2.999 šema se header→column→payload poklapa tačno.
Ranijih 17 fallback slučajeva sadrži `kind 3` descriptor od 12 B: member index,
indirect count, payload size i decompression amount. Na punom fajlu svih 20.250
takvih delova ima jedinstven skriveni member kandidat i tačnu count/size vezu.
Firmware helper `FUN_08335a58` potvrđuje posebne logical part amount vrednosti:
tipovi `0x90`/`0xa0` daju 2, `0xb0` daje 1, dok `parseDescriptions` eksplicitno
postavlja `0xc0`/`0xd0` na 1 i optional članu dodaje dva sintetička in-memory
dela. Corpus pravila dodatno pokrivaju array-composite deo, deljeni class/
structure `0x90` deo i dva optional scalar dela u `VidTable`. Rezultat je
42.066/42.066 egzaktnih `(composite, member, part_index)` grupisanja.

`serialize_logical_schema` i `serialize_exact_column_table` zatvaraju i writer
format zaglavlja: svih 42.066 schema blokova, descriptor tabela i kompletnih
decoded chunk-ova reprodukuje se identično bajt-po-bajt. To još ne znači da su
generisane nove semantičke object vrednosti.

Prvi izvršni deo tog sloja je `tools/orion_object_writer.py`. Nad
`out/basic_graph_export/nodes.jsonl` pravi `out/orion_point_llh_writer/` sa
novim `Map/PointLlh` decoded chunkom: 100 redova, tri signed `0x35` code-1
kolone (`Longitude`, `Latitude`, `Height`), 1.200 B payloada i ukupno 1.303 B.
Longitude/latitude su deterministički WGS84 `degree × 10^7`, a height je
konzervativno nula. Generator sam zahteva šest provera: identične schema/table/
ceo-chunk bajtove posle reparsiranja, potpuno member grupisanje, identične
dekodirane vrednosti i header payload size. Sve prolaze. Ovo dokazuje stvarno
emitovanje novih scalar objekata, ali ne ATLAS kompatibilnost celog fajla:
object reference, tri još neprotumačene header reči, catalog/index, blok
kompresija, apsolutni offseti i container checksumovi ostaju naredni sloj.

`tools/orion_schema_extract.py` čuva samostalni originalni dokaz u
`out/orion_graph_schema_sample/`. U prvom PSD3 graph chunku class handle-i se
numerišu od 1 po schema redosledu (`Edge=993..1572`, `Node=1573..1955`), dok je
0 external/null sentinel. `From` ima 538 nenultih i 42 nulte reference, `To`
556 nenultih i 24 nulte; svaka nenulta vrednost je unutar Node opsega.
Writer ovo reprodukuje nad MIB sample-om, a fizički profil je razrešio i ranije
otvoreni slučaj. `EdgeRoadElement.Attributes` je implicitna 1:1 struktura bez
serialized dela. Sledeća kolona je direktni `NodeRoadElement.PointGeometry`
handle i predstavlja tačnu permutaciju svih 383 PointGeometry objekata u opsegu
`30..412`. Četvorobitni niz iza nje je `Vias` cardinality (383 vrednosti, zbir
1.094), narednih 1.094 `uint16` vrednosti su Edge handle-i, a treći deo je
optional/default. Novi integrisani sample zato ima PointGeometry
`1..100`, Edge `101..200`, Node `201..300`, `From/To` i 76 lokalnih `Vias`
referenci u jednom 2.198 B decoded chunku. Svih 12 self-checkova prolazi, kao i
ponovljeni puni corpus roundtrip za svih 42.066 originalnih PSD3 chunkova.

`tools/orion_centerline_writer.py` čita postojeći
`out/orion_clothoid_source/clothoid_edges.jsonl` i za svaki source segment pravi
zaseban dvotačkasti, zero-curvature part. Time su source endpoint-i sačuvani bez
izmišljanja tangent continuity na poligonskim uglovima. Sample od 100 edge-ova
ima 824 part-a, 1.648 `PointLld` redova i 17.255 B. Clothoid handle-i su
`1..100`, Edge handle-i `101..200`; svih deset schema/table/value/range/
geometrijskih self-checkova i checksumovi prolaze. `Direction` koristi originalni
fizički u16 full-circle opseg; runtime prikaz ugla ostaje predmet device testa.

`tools/orion_merged_graph_writer.py` spaja oba dokazana sloja tek kada se edge
ID-jevi i njihov redosled potpuno poklope. Sample od 100 node/100 edge redova
daje jedan 19.849 B decoded chunk: Adas `1`, AudiUrban `2`, Urban `3..4`,
PointGeometry `5..104`, Clothoid `105..204`, Edge `205..304`, Node `305..404`,
uz 824 part-a, 1.648 PointLld redova, 300 property i 76 Vias referenci. Svih 21
provera zajedničkog handle prostora, fizičkih kolona, property redosleda,
topologije, geometrije i source poravnanja prolazi.

`tools/orion_property_layout_profile.py` zatvara strukturni ugovor prvog od pet
preostalih koraka. Na originalnom sample-u 580 `Attributes.Parts` vrednosti daje
586 `PropertyD1` lista; svaka ima 3–4 property handle-a, ukupno 1.760. Svaki
handle pada u Adas/AudiUrban/SpeedLimit/Urban class opseg, a zbir cardinality
vrednosti tačno odgovara flattened nizovima. Novi
`tools/orion_property_corpus_profile.py` profilisao je ceo originalni ATLAS:
8.081 graph/property chunk, 1.511.928 lista i 4.801.622 validna handle-a. U
1.511.916 lista potvrđen je redosled Adas→Urban→AudiUrban. Referencirani trojci
su samo `0+0+0`, `0+1+0` i `0+1+1`, pa je AudiUrban strogi podskup Urban-a.
Merged writer zato emituje tri handle-a po edge-u, sa firmware-backed Urban
izborom između redova 0/1. Na 4.333 originalna baseline-only chunk-a Adas je
uvek nula. AudiUrban ostaje nulti fallback dok se ne dokaže njegov uži MIB
source; susedni geometry bitovi ne zadovoljavaju subset invariant. Opcione klase
i AudiUrban mapiranje ostaju sledeći podkorak stavke 2.

`tools/run_psd15_profile_re.py` dodatno automatizuje Ghidra dokaz nad MHI2
`libATFPSDAdapter15.so`: `FUN_00036050` prolazi ADAS interface profile kroz 46
tipizovanih konvertera ka PSD1.5 storage-u. Binar je stripped, a njegov
`libATFPSDAdapter15.so-20160718160238.sym` debuglink (CRC `0x6f528a2a`) nije u
firmware-u. Zato se redosled vtable metoda ne proglašava javnim imenom profila
bez nezavisnog enum-a ili jedinstvene formule konverzije.

Stavka o jeziku je zatvorena. `worldCountry` trailer direktno mapira zvanične
jezičke ID-jeve, a firmware VA `0x012a97e0` dokazuje izbor pisma: base se bira
podrazumevano, dok ID u consumer transliteration listi zahteva upareni
alternate. Ne postoji dokaz za univerzalni redosled različitih jezika ili
aliasa, zato adapter čuva sve i očekuje eksplicitnu UI/nav politiku.

Zato se trenutni rezultat može odmah koristiti za razvoj i testiranje
`NodeRoadElement`/`EdgeRoadElement`/centerline adaptera, ali se još ne sme
predstaviti kao gotova navigaciona baza za ubacivanje u uređaj.
