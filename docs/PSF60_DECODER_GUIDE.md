# PSF60 dekoder i alati — detaljan vodič (SR)

> Ovo je originalni radni README projekta, zadržan kao detaljan vodič kroz
> `tools/psf_decode.py` i ostale alate po fazama. Kratak pregled na engleskom je
> u korenskom [README.md](../README.md), redosled čitanja u [docs/README.md](README.md).

Read-only projekat za izdvajanje Audi MHI2 navigacionog parsera iz firmware-a
i pretvaranje MIB mapa u proverljiv, strukturiran izlaz. Alat ne radi flash,
patch niti bilo kakav upis u MMI jedinicu.

## Trenutni rezultat

- Firmware `MHI2_ER_AU57x_K3663_1_MU1425_AIO.7z` sadrži MMX2 QNX6 image.
- Aktivni navigacioni format je `PSF2DDTM`, detaljna verzija
  `60DREID4ADAS7`.
- Glavni parser je `/navigation/libPathfinderApp.so` (ARM/QNX,
  PNAV Core 10.2.5).
- PSF kompresija iz firmware-a je potvrđena: `1 = LZMA-Alone`,
  `2 = zlib` sa četvorobajtnom LE veličinom izlaza. Lokalni Serbia PSF
  uzorci koriste LZMA-Alone.
- Dekoder čita zaglavlje, blokove, metadata TLV, poznate indekse klastera,
  LZMA payload-e, klasterske root-footer čvorove, imena i Landmark objekte.
- Za `Basic.psf` je potvrđeno svih 65.527 streamova i 9.051 klaster; svih
  26.056 direktno indeksiranih payload-a ima sačuvano poreklo indeksa, a
  dodatnih 689 lead/middle/finalizer streamova vezano je za 233
  `CombinedDesc` zapisa. Njihovih 79 finalizer direktorijuma povezuje još
  1.590 jedinstvenih payload-a. Preostali članovi su vezani za svoj klaster.
- Napravljen je kompletan i proverljiv storage/source layer za potvrđeni
  strict scan scope (`max_output_size=64 MiB`, `permissive_lzma=false`):
  65.527 redova manifesta i 82.275.083 B raspakovanih blokova u
  [`out/serbia_basic_source/`](../out/serbia_basic_source/).
- Prvi semantički Basic sloj je globalno potvrđen nad svih 3.336 glavnih
  klastera: 838.433 fiksna edge deskriptora, 717.730 promenljivih node zapisa
  i tačno 838.433 pripadajuća geometry zapisa. Sve razrešive node/edge veze
  prolaze proveru u oba smera. Izveštaj i prvi normalizovani source uzorak su
  u [`out/basic_semantic_probe/`](../out/basic_semantic_probe/).
- Unutrašnji geometry grammar je zatvoren za svih 838.433 edge zapisa:
  dobijeno je 903.487 tačno omeđenih firmware subrecord-a bez ijednog
  neobjašnjenog bajta između potvrđenih granica. Izveštaj je u
  [`out/basic_geometry_grammar/`](../out/basic_geometry_grammar/).
- Firmware-potvrđeni koordinatni decoder pretvara svih 838.433 edge-a u
  903.487 uređenih delova sa ukupno 3.960.735 Mercator/WGS84 tačaka. Svih
  2.153.761 potpisanih delta-parova je obrađeno bez greške i nijedna tačka
  nije izašla iz bbox-a svog klastera. Izveštaj i source uzorak su u
  [`out/basic_geometry_decode/`](../out/basic_geometry_decode/).
- Firmware `handle2` directory i record header su potvrđeni nad svih 3.336
  klastera: 838.433 edge reference vode na 182.377 jedinstvenih semantic
  recorda, a svih 41.671 flag-selected pokazivača ostaje unutar svog recorda.
  Direktni `SDString` grammar dekodira 271.823 primarna i 262.187 fonetska
  stringa bez ijedne greške. Izveštaji su u
  [`out/basic_handle2_directory/`](../out/basic_handle2_directory/) i
  [`out/basic_handle2_text_decode/`](../out/basic_handle2_text_decode/).
- Jezički ID-jevi više nisu nepoznati. Basic `worldCountry` trailer direktno
  daje `30=Bosnian`, `31=Albanian`, `33=Serbian`, `48=Montenegrin`; zasebne
  Albania i Bosnia mape potvrđuju iste vrednosti. Svih 271.823 fizičkih
  tekstualnih stavki grupisano je u 151.818 logičkih imena, uključujući
  120.005 potpuno validnih base→transliteration parova bez orphan/mismatch
  slučaja. Dokazi su u [`out/basic_world_country_languages/`](../out/basic_world_country_languages/)
  i [`out/basic_handle2_name_profile/`](../out/basic_handle2_name_profile/).
- Stabilni graph/source interfejs spaja delove u 838.433 kontinuirana
  centerline-a sa 3.895.681 tačkom i izvozi 717.730 `NodeRoadElement`
  kandidata sa `from/to` vezama. Uz to, 549.784 edge-a imaju 995.298
  `name_candidates` referenci sa fonetikom, odnosno 554.508 referenci na
  logička imena. Svih 65.054 unutrašnjih spojeva i sve stroge endpoint provere
  su tačne. Rezultat je u
  [`out/basic_graph_export/`](../out/basic_graph_export/).
- AdvancedRouting i ADAS su lossless parsirani preko celog korpusa i spojeni
  sa Basic edge-ovima u
  [`out/pre_writer_layers_source/`](../out/pre_writer_layers_source/): 838.433
  ADAS recorda, 838.313 regularnih AdvancedRouting recorda i 1.188 dodatnih
  recorda u sedam supra klastera. Unutrašnja javna semantika tih recorda još
  nije kompletno imenovana.
- Pre-writer clothoid adapter je proverio svih 838.433 edge-a i pretvorio
  3.057.085 non-zero polilinijskih krakova u geometrijski identične
  zero-curvature clothoid segmente. Dokaz je u
  [`out/orion_clothoid_source/`](../out/orion_clothoid_source/).
- Read-only target profiler je na originalnom 3G Plus `PSD3` zatim prošao ceo
  fajl: 43.402 bloka, 42.081 raspakovan deo i 42.066 egzaktno povezanih
  logičkih/fizičkih column tabela. Svih 649.210 codec bajtova je `1`, a svaki
  payload prolazi byte-identical split→assemble proveru. Svaka tabela je takođe
  grupisana do `(composite, member, part_index)`, a schema + descriptor tabela +
  payload reprodukuju ceo decoded chunk identično bajt-po-bajt. Writer-ov
  konzervativni fizički put zato je code 1. Skripta i dokazi su
  `tools/orion_psd_reference_profile.py` i
  [`out/orion_psd_reference/`](../out/orion_psd_reference/) odnosno
  [`out/orion_psd_reference_full/`](../out/orion_psd_reference_full/).
- `tools/orion_column_codec.py` i `tools/run_orion_column_codec_re.py` čuvaju
  ponovljivi firmware dokaz, code-1 layout/assembler i ispravno modelovan
  rekurzivni code-3 header; artefakti su u
  [`out/firmware_re/orion_column_codec/`](../out/firmware_re/orion_column_codec/).
- `tools/orion_object_writer.py` je izvršni writer: iz MIB
  `nodes.jsonl` pravi novu decoded Orion `Map/PointLlh` šemu i tri signed
  `0x35` code-1 kolone, pa obavezno radi parser/value/byte-identical
  samoproveru. Sa `--edges` dodatno emituje direktne globalne
  `EdgeRoadElement.From/To → NodeRoadElement` handle kolone, po obrascu koji je
  `tools/orion_schema_extract.py` automatski potvrdio nad originalnim PSD3.
  Lokalni 100-node/100-edge rezultat i checksumovi su u
  [`out/orion_point_llh_writer/`](../out/orion_point_llh_writer/). Ovo nije još
  ATLAS container niti baza spremna za uređaj.
- Ponovljivi Ghidra batch `tools/run_psd15_profile_re.py` potvrđuje zaseban
  MHI2 ADAS-interface → PSD1.5 konverzioni sloj sa 46 tipizovanih convertera;
  artefakti su u
  [`out/firmware_re/psd15_profiles/`](../out/firmware_re/psd15_profiles/).
- `Landmark.psf` je preveden u 78 semantičkih objekata i WGS84 GeoJSON:
  [`out/serbia_landmarks.geojson`](../out/serbia_landmarks.geojson).

Ovo je strukturirani izvoz iz isporučene mape, ne originalni HERE/NDS izvorni
projekat niti rekonstrukcija vlasničke šeme jedan-prema-jedan.
Redosled implementacije i trenutno zatvorene/otvorene stavke vode se u
[`docs/IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).
Za nastavak rada u drugom agentu postoji kompletan operativni checkpoint u
[`docs/CLAUDE_HANDOFF.md`](CLAUDE_HANDOFF.md).

## Brzi početak

Pregled i provera PSF omotača, `content.pkg` potpisa i SHA-1 delova:

```bash
python3 tools/psf_decode.py inspect MAP.psf \
  --package content.pkg --hashes hashes.txt
```

Tipizovani metadata zapisi:

```bash
python3 tools/psf_decode.py metadata MAP.psf --limit 20
python3 tools/psf_decode.py metadata MAP.psf --field-id 0x13f
```

Poznati indeksi klastera (`Basic`, `Landmark`, `ADAS`,
`AdvancedRouting` se prepoznaju po imenu):

```bash
python3 tools/psf_decode.py cluster-index Basic.psf --kind basic-known
python3 tools/psf_decode.py cluster-index Basic.psf \
  --kind basic-known --entries --limit 10
python3 tools/psf_decode.py extract-indexed Basic.psf \
  --kind basic-known --output decoded-index
```

Otkrivanje i raspakivanje firmware-kompatibilnih LZMA/zlib tokova u zadatom
scan scope-u, uključujući slojeve čiji indeks još nije semantički imenovan:

```bash
python3 tools/psf_decode.py scan-codecs MAP.psf
python3 tools/psf_decode.py extract-streams MAP.psf --output decoded-streams
```

`extract-streams` podrazumevano pravi jedan `payloads.bin` i
`manifest.ndjson`, što je praktično i za desetine hiljada malih klastera.
Opcija `--layout files` pravi poseban fajl za svaki payload.

Struktura kontigvnih klastera, gapova i kompaktnih root footer-a za isti
strict scan scope:

```bash
python3 tools/psf_decode.py stream-layout Basic.psf \
  --output basic-layout.json
```

Deterministički source layer sa SHA-1/SHA-256 proverama, poreklom indeksa,
root tipovima i offsetom svakog raspakovanog bloka:

```bash
python3 tools/psf_decode.py export-source Basic.psf \
  --output basic-source --layout container

# Alternativno: blocks/000000.bin, blocks/000001.bin, ...
python3 tools/psf_decode.py export-source Basic.psf \
  --output basic-source-files --layout files
```

Izlaz sadrži `manifest.jsonl`, `index_references.jsonl`, `layout.json`,
`source_summary.json`, `CHECKSUMS.sha256` i `payloads.bin` ili direktorijum
`blocks/`. Source schema v6 u svakom manifest redu jasno odvaja
`wrapper_offset/wrapper_size + sha1_stored` od
`codec_stream_offset/codec_stream_size + sha1_compressed`; zatim čuva raw
offset/veličinu i hash, klaster, index provenance i root tip. `compressed_size`
je kompatibilni alias za `codec_stream_size`. `layout.json` dodatno čuva
CombinedDesc i finalizer-directory veze. Manifest ima 28.335 streamova sa
kanonskom indeksnom anotacijom, dok `index_references.jsonl` čuva svih 35.371
referenci, uključujući duplirane dual/triple i spatial/key poglede, bez
gubitka provenance-a.

Automatska inferencija i potpuna provera Basic node/edge/geometry granica:

```bash
python3 tools/basic_semantic_probe.py Basic.psf \
  --output basic-semantic --sample-limit 100
```

Skripta sama izvodi layout kandidate, obrađuje svih 3.336 klastera, proverava
edge↔node veze i uparuje svaki edge sa geometry zapisom. Piše `report.json`,
`edge_sample.jsonl` i `CHECKSUMS.sha256`. `--sample-limit 0` emituje svih
838.433 edge source zapisa; ograničeni uzorak je praktičniji dok je unutrašnja
geometrijska komanda još u rekonstrukciji.

Sledeći automatski sloj deli svaki edge geometry zapis na firmware subrecord-e:

```bash
python3 tools/basic_geometry_grammar.py Basic.psf \
  --output basic-geometry-grammar --sample-limit 100
```

Jedinstveni layout (`record header=2`, subrecord `base=3`, `stride=2`) izveden
je iz podataka i zatim proveren nad svih 903.487 subrecord-a.

Numerički koordinatni sloj radi kao samostalni streaming decoder:

```bash
python3 tools/basic_geometry_decode.py Basic.psf \
  --output basic-geometry-decode --sample-limit 100
```

Skripta implementira firmware formulu za u16/u32 koordinate, cluster skalu,
coordinate-table endpoint-e i potpisane `int8` delta-parove, zatim proverava
svaku dobijenu tačku. Piše `report.json`, `edge_geometry_sample.jsonl` i
`CHECKSUMS.sha256`; `--sample-limit 0` emituje svih 838.433 normalizovanih
edge zapisa. Tagged extension sadržaj ostaje sačuvan kao raw polje.

Firmware-potvrđeni `handle2` directory, record i direktni tekst slojevi rade
kao odvojene proverljive skripte:

Kompletna language/name stavka može se ponoviti jednom komandom; runner sam
pokreće world-language, name-profile i puni graph validator i proverava da se
njihovi ID-jevi i zbirni brojevi slažu:

```bash
python3 tools/run_basic_name_stage.py Basic.psf \
  --output basic-name-stage --sample-limit 100 \
  --transliterate-identifier 30 \
  --transliterate-identifier 33 \
  --transliterate-identifier 48
```

Pojedinačne komande za dijagnostiku su:

```bash
python3 tools/basic_handle2_directory.py Basic.psf \
  --output basic-handle2-directory --sample-limit 100
python3 tools/basic_handle2_text_decode.py Basic.psf \
  --output basic-handle2-text --sample-limit 100
python3 tools/basic_world_country_languages.py Basic.psf \
  --output basic-world-languages
python3 tools/basic_handle2_name_profile.py Basic.psf \
  --output basic-name-profile --sample-limit 100
```

Prva validira svaki edge→record pokazivač, record granice, auxiliary selector
i section offset. Druga implementira firmware `SDString` cursor za tagovane
UTF-8/Latin-1/UTF-16 vrednosti i fonetske parove. Treća čita zvanične jezičke
ID-jeve iz `worldCountry` recorda, a četvrta proverava raspored, pismo,
base/transliteration parove i geografski korpus. Sve prolaze ceo ulaz;
`--sample-limit` ograničava samo NDJSON izlaz.

Albania/Bosnia dokaz se sam ponavlja direktno iz 7z arhiva, bez ručnog
raspakivanja:

```bash
python3 tools/run_basic_identifier_crosscheck.py P470_N60S5MIBH3_EU.7z \
  --output basic-identifier-crosscheck --sample-limit 20
```

Validirani graph/source za Orion adapter:

```bash
python3 tools/basic_graph_export.py Basic.psf \
  --output basic-graph --sample-limit 100

# Firmware-style Latin/transliteration izbor za BS/SR/CNR bucket-e:
python3 tools/basic_graph_export.py Basic.psf \
  --output basic-graph-latin --sample-limit 100 \
  --transliterate-identifier 30 \
  --transliterate-identifier 33 \
  --transliterate-identifier 48
```

`nodes.jsonl` i `edges.jsonl` mapiraju se na Orion
`NodeRoadElement`/`EdgeRoadElement`, `From`/`To`, `CenterlineGeometry`, `Parts`
i `PointLld`, kao i sirove `NameCandidates` i grupisane `logical_names` sa
jezikom, base oblikom, transliteracijom i nepraznom fonetikom. Skripta uvek
validira ceo graf; `--sample-limit 0` zapisuje svih 717.730 node i 838.433
edge zapisa. Bez opcije bira se base oblik. Ponovljivi
`--transliterate-identifier` tačno oponaša firmware VA `0x012a97e0`: za taj
jezik zahteva i bira upareni alternate. Svi jezici i aliasi ostaju u source-u;
globalni UI izbor jezika se ne izmišlja. Granica do kompletnog `.ATLAS`
writer-a je opisana u
[`docs/ORION_ADAPTER.md`](ORION_ADAPTER.md).

Prvi autonomni Orion scalar writer:

```bash
python3 tools/orion_object_writer.py \
  out/basic_graph_export/nodes.jsonl \
  --edges out/basic_graph_export/edges.jsonl \
  --output out/orion_point_llh_writer \
  --limit 100 --edge-limit 100
```

`--limit 0 --edge-limit 0` obrađuje cele prosleđene JSONL fajlove. Izlaz sadrži
PointLlh i zaseban graph-reference binary, kao i
`integrated_graph.decoded.bin` sa PointGeometry, Edge/Node, `From/To` i `Vias`
kolonama, provenance redove, manifest sa granicom implementacije i SHA-256
checksumove.

Autonomni Orion centerline writer:

```bash
python3 tools/orion_centerline_writer.py \
  out/orion_clothoid_source/clothoid_edges.jsonl \
  --output out/orion_centerline_writer \
  --limit 100
```

On pravi `centerline_graph.decoded.bin` sa `PointLld`, dvotačkastim
zero-curvature part-ovima, Clothoid objektima i direktnim Edge centerline
handle-ima. Sample od 100 edge-ova ima 824 part-a i 1.648 PointLld redova;
ovaj zasebni binary ostaje kontrolni artefakt.

Objedinjeni topology + centerline writer:

```bash
python3 tools/orion_merged_graph_writer.py \
  out/basic_graph_export/nodes.jsonl \
  --edges out/basic_graph_export/edges.jsonl \
  --clothoids out/orion_clothoid_source/clothoid_edges.jsonl \
  --output out/orion_merged_graph_writer \
  --node-limit 100 --edge-limit 100
```

`merged_graph.decoded.bin` sadrži sve dosadašnje graph i centerline objekte u
jednom globalnom handle prostoru, kao i `Attributes.Parts`, trodelni
`PropertyD1.Values`, po jedan deljeni `AdasProperty`/`AudiUrbanProperty` i dva
`UrbanProperty` objekta (`0/1`). Urban handle se za svaki edge bira iz dokazanog
MIB geometry secondary flag bit-a 5. Originalni sample contract se reprodukuje sa:

```bash
python3 tools/orion_property_layout_profile.py \
  out/orion_graph_schema_sample/sample_00.schema.json \
  out/orion_graph_schema_sample/sample_00.decoded.bin \
  --output out/orion_property_layout_profile
```

Property contract cele originalne EU mape profilisan je lokalno sa:

```bash
python3 tools/orion_property_corpus_profile.py \
  /putanja/do/originalnog/PSD3.ATLAS \
  --output out/orion_property_corpus_profile --quiet
```

Puni prolaz potvrđuje 8.081 graph/property chunk, 1.511.928 lista i 4.801.622
validne Property reference. Obični Urban je firmware-backed i puni MIB profil
broji 448.174 urban edge-a od 838.433. Adas nula je potvrđena originalnim
korpusom; AudiUrban ostaje konzervativna nula jer njegovo uže source mapiranje
još nije dokazano. Pre ATLAS pakovanja ostaju AudiUrban i opcioni
speed/lane/restriction sloj.

Ponovljivi lokalni firmware dokaz za Urban:

```bash
python3 tools/run_basic_urban_semantics_re.py \
  --output out/firmware_re/basic_urban_semantics
```

AudiUrban istraga je trenutno na korigovanom kandidat checkpointu: secondary
bit 6 se dekodira na output `+0x1e9` odnosno cached-edge `+0x1ed`. Ranije
pretpostavljeni route-edge `+0x281` je sada identifikovan kao radno stanje
`OnBGeoPOIService` i nije semantički dokaz. AudiUrban formula zato još nije
dokazana, pa writer i dalje bezbedno emituje AudiUrban nulu. Tačan nastavak i hash-evi su u
`out/firmware_re/audiurban_candidate_phase/report.json`; puni Ghidra skenovi
se izvršavaju paralelno kroz `tools/run_ghidra_sharded_grep.py`.

Za nezavisni corpus dokaz dodat je `tools/orion_graph_spatial_probe.py`.
Originalni 3G+ Balkan je lociran u PSD1, a osam checksumovanih decoded graph
chunkova iz Crne Gore je sačuvano u
`out/orion_graph_spatial_probe_serbia_02/`. Time su originalna geometrija i
AudiUrban objekti prvi put zajedno izdvojeni za sledeće per-edge uparivanje.
`tools/orion_edge_property_decode.py` već je vezao Property liste za svih
1.593 edge-a iz tog uzorka; lossless rezultat je u
`out/orion_edge_properties_montenegro/`. Novi
`tools/orion_edge_geometry_decode.py` je zatim za svih 1.593 edge-a razrešio
From/To preko Node/PointGeometry do originalnih PointLlh koordinata i sačuvao
proverenu `ClothoidCenterlineGeometry` referencu. Potpisani spoj sa Property
listama je u `out/orion_edge_source_montenegro/`; sledeće se dekodiraju
centerline Parts/PointLld i rade prostorno uparivanje sa MIB edge-ovima.

Taj decode sada radi paralelno kroz
`tools/orion_centerline_geometry_decode.py`; prošireni corpus od 64 chunka ima
21.570 edge-a i 110.965 originalnih PointLld redova. Lokalni MIB ekstraktor je
pregledao svih 838.433 edge-a, a corridor matcher je dobio 148 high i 643
medium 1:N kandidata. Rezultat izričito odbacuje geometry secondary bit 6 kao
samostalnu AudiUrban formulu. Sledeća granica je topološki chain matcher, jer
se edge segmentacija između dve generacije značajno razlikuje.
Profil svih osam MIB secondary bitova na 148 high parova nije pronašao
jednobitnu AudiUrban formulu (najbolji bit 5: 56,46%; bit 6: 31,69%).
Prvi from/to topology-chain filter dodat je u
`tools/orion_mib_topology_chain.py`: potvrđuje 6 high + 20 medium čistih 1:N
lanaca od 791 corridor kandidata. Sledeće je bounded graph search za kratke
spojne edge-ove koji nisu izabrani pointwise corridor glasanjem.
`tools/orion_mib_bounded_graph_match.py` završava taj korak: sa 80 m i najviše
12 hopova potvrđuje 8 high + 50 medium putanja; 120 m ne daje dodatne
pouzdane rezultate. Sledeći filter mora koristiti stabilne atribute, a ne širi
geometrijski prag.
Kompaktni MIB corpus sada nosi direction/automotive/speed/lane/passing
atribute. Profil 58 prihvaćenih putanja nije našao dovoljno jak pozitivan
identity signal; sledeće se dekodiraju pune vrednosti odgovarajućih originalnih
Orion Property objekata.
To je sada završeno za svih 64 originalna chunk-a: automatski poravnati i
dekodirani corpus sadrži 748 SpeedLimit, 390 NumberOfLanes, 263
PassingRestriction i 54 SpeedBumps objekta. Uključeni su suženi fizički tipovi,
tri indirect-dictionary kolone i raw `TimeDomain` delovi, bez nagađanja enum
naziva. Izlaz je `out/orion_edge_properties_montenegro_04/`; naredni korak je
value-level profil prema 58 prihvaćenih MIB bounded putanja.
Profil je izvršen: samo jedan put ima speed vrednost na obe strane i ona se ne
poklapa; lane/passing nemaju nijedan both-present par. To sprečava prerano
pojačavanje match score-a atributima i ostavlja sledeću granicu na stabilnijem
topology/name/direction identitetu i širem originalnom uzorku.
Širenje sada radi jednim `run_orion_cross_version_corpus.py` pozivom. Još 192
chunk-a podižu zbir na 256 chunkova, 73.679 edge-a i 511.136 PointLld redova;
zbir bounded rezultata je 10 high + 64 medium. Direction profiler potvrđuje
node-povezan redosled putanje, ali 66/74 putanja je dvosmerno, a retki raw
Orientation uzorci nisu dovoljno konzistentni za identity signal. Sledeći
korak je name/road-class ili ručno potvrđena ista deonica.
`orion_item_identifier_profile.py` je zatim proverio `Item.Identifiers` nad
svih 256 chunkova: payload tačno daje 134.581 sirovih 64-bitnih redova, ali
3.780 poređenja ponovljenih edge vrednosti nijednom ne daju istu ili obrnutu
geometriju. Polje zato nije jedinstveni edge ID. Dokazni izlaz je
`out/orion_item_identifiers_montenegro_04_06/`; naredna, još nepokrenuta faza
je bila provera moguće road-group/name-key semantike prema MIB imenima i klasama.
Ona je sada završena u `mib_graph_spatial_extract.py` schema-v3 i
`orion_mib_name_identity_profile.py`: 23 ponovljena ID para nemaju nijedan
disjoint name rezultat, ali svi dele bar jedan isti MIB kandidat. To potvrđuje
cross-chunk grouping signal, ali ne dokazuje nezavisnu name-key semantiku niti
dozvoljava korišćenje polja kao jedinstvenog edge ID-ja.

Sledeća podfaza je zatvorena sistemskim schema inventarom i punim VidTable
profilom. `tools/orion_schema_name_inventory.py` je u 8 procesa pregledao
PSD0/PSD1/PSD3: 219.365 graph `Map` šema nema road-name/road-class kolonu;
PSD3 dodatno ima 33.985 `VidTable` šema. CTY0 je zaseban 3D city-model sloj
(213.041 `Map` šema), takođe ne izvor road naziva. Zato originalni naziv/klasa
nije sakriven kao još nepročitana kolona u poznatom PSD graph objektu.

`tools/orion_vidtable_identifier_profile.py` je zatim bez 32-bitnog skraćivanja
proverio svih 33.985 VidTable tabela i 94.974.728 raw `AtlasIds` dictionary
vrednosti. Tačno 65.841 od 130.929 jedinstvenih `Item.Identifiers` vrednosti
poklapa se u svih 64 bita; pogođenih 69.253 redova su svi
`EdgeRoadElement`. Time je dokazano da `Item.Identifiers` i
`VidTable.AtlasIds` dele isti ID domen. Sledeća granica je dekodiranje
VidTable row/dictionary mapiranja zajedno sa `XacVectorOffsets`, pa čitanje
odgovarajućeg XAC zapisa; veza do konkretnog naziva/road-class još nije
dekodirana.

Prvi deo te granice je sada završen skriptom
`tools/orion_vidtable_row_mapping.py`. Nad kompletnim PSD3 ona je strogo
ekspandirala 13.871 direct i 20.114 indirect tabela u 170.571.814 poravnatih
`AtlasId → XacVectorOffset` redova. Svi indirect dictionary indeksi su u
opsegu, count kolone se poklapaju, a offseti su jedinstveni unutar svake
tabele. Za 65.841 relevantnih Item ID-eva izdvojeno je 299.486 konkretnih
redova u `out/orion_vidtable_row_mapping_montenegro_04_06/`. Sledeći mali
korak, fizičko vezivanje za XAC, takođe je završen.

`tools/orion_xac_vector_bind.py` parsira FLDB direktorijume i skenira kompletan
fizički prostor sva tri XAC sharda, uključujući continuation zone koje nisu
pokrivene imenovanim `.xac` stavkama. Pronađeno je 47.176 `VEKTORBLOCK`
markera; kompletan niz od 33.985 VidTable row-count vrednosti postoji u njemu
istim redom i svako uparivanje ima jednak count. Count+order jednoznačno
određuje 33.923 bloka; za preostalih 62 mala skupa ponovljenih count vrednosti
sačuvano je svih 147 kandidata, bez lažne tvrdnje da je njihov fizički izbor
već dokazan. Svih 33.985 izabranih offset opsega staje ispod konzervativne
fizičke granice narednog markera/kraja FLDB stavke. Time je dokazan
vector-block lokalni namespace. Rezultat je u
`out/orion_xac_vector_binding/`.

Unutrašnja baza je zatim zatvorena firmware-backed skriptom
`tools/orion_xac_vector_offset_resolve.py`. NavCore lookup ima dva režima:
legacy/direct koristi `marker + XacVectorOffset`; version-5 indexed režim čita
BE32 index-table offset na `+0x6c`, BE16 broj indeksa na `+0x70` i flag 1 na
`+0x72`, pa cilj računa kao `marker + 2*BE16(index_table + offset)`. Puni
8-worker prolaz ponovo je dekodirao svih 170.571.814 offseta: 9.648 tabela je
direct, 24.337 indexed, svaki target je u granici i svaki počinje firmware
očekivanim `0xc0` vector potpisom. Struktura je razrešila 41 od ranija 62
slučaja; dokazani `_2.xac` owner invariant na 33.929 jednoznačnih named-XAC
veza i globalni red razrešili su ostalih 21. Konačno je jednoznačno svih
33.985 tabela, bez ostatka.

Za sledeći decoder materijalizovano je svih 299.486 relevantnih
`AtlasId → XAC target` redova, sa DB fajlom, markerom, relativnim i apsolutnim
offsetom i 16-bajtnim prefixom u
`out/orion_xac_vector_offset_resolution/selected_item_targets.jsonl`.

### XAC vector record i name-reference checkpoint (2026-09-03)

Sledeći sloj je sada takođe prošao ceo relevantni korpus. Četiri nove
ponovljive skripte — `orion_xac_vector_record_layout.py`,
`orion_xac_vector_payload_probe.py`, `orion_xac_vector_branch_profile.py` i
`orion_xac_vector_name_refs.py` — čitaju **299.486** već razrešenih XAC
targeta uz NavCore kao odvojeni firmware ulaz. Ta razdvojenost je bitna:
descriptor tabela je u NavCore-u, ne u XAC bazi; ranija probna interpretacija
koja je descriptor čitala iz XAC mmap-a je povučena i ne koristi se kao dokaz.

Firmware funkcija `get_names_of_vector` potvrđuje record gramatiku. Svaki
relevantan target počinje record-om čiji je `byte0 & 0xc0 == 0xc0`; 11-bitni
key je sastavljen iz `byte2/byte3`, a record može da nasledi key/header preko
backreference-a. Key bira četvorobajtni descriptor iz NavCore tabele na VA
`0x085b4fe8`. Descriptor i efektivni flagovi vode cursor kroz opcione
runtime/static delove i eventualni name-reference niz. Puni 8-worker layout
prolaz je završio svih 299.486 recorda bez parse greške; vidi
`out/orion_xac_vector_record_layout/`.

Name flag je prisutan u 25.110 recorda. Njihov nastavak je sada dekodiran kao
14-bitni packed ID niz sa continuation bitom; pronađeno je 44.722 reference
prema 8.877 različitih name ID-jeva, bez unterminated ili invalidnog niza.
To su reference, **ne još tekstualni nazivi**. Firmware resolveri
`FUN_082538e4`, `FUN_082539f0` i `FUN_08253ba0` pokazuju da se ID zatim
razrešava kroz zaseban `xac_name` direct/compressed blok i njegov cache. Zato
sledeći posao nije više pogađanje XAC recorda, već nalaženje i rekonstrukcija
inicijalizacije/učitavanja `xac_name` podataka, pa tek onda izvođenje stvarnog
stringa, jezika i name type-a. Dokazi i ponovljivi izlazi su u
`out/orion_xac_vector_name_refs/` i
`out/firmware_re/orion_xac_bridge/`.

Ponovljivi lokalni prolaz:

```bash
python3 tools/orion_xac_vector_bind.py \
  --tables out/orion_vidtable_row_mapping_montenegro_04_06/tables.jsonl \
  --xac-db /putanja/pkgdb/XAC/kN221EUx01_0.db \
  --xac-db /putanja/pkgdb/XAC2/kN221EUx01_1.db \
  --xac-db /putanja/pkgdb/XAC3/kN221EUx01_2.db \
  --output out/orion_xac_vector_binding

python3 tools/orion_xac_vector_offset_resolve.py \
  /putanja/pkgdb/PSD3/mapa.ATLAS \
  --bindings out/orion_xac_vector_binding/bindings.jsonl \
  --candidates out/orion_xac_vector_binding/ambiguous_binding_candidates.jsonl \
  --selected-rows out/orion_vidtable_row_mapping_montenegro_04_06/selected_item_rows.jsonl \
  --output out/orion_xac_vector_offset_resolution --jobs 8
```

Landmark u NDJSON ili GeoJSON:

```bash
python3 tools/psf_decode.py landmarks Landmark.psf --limit 5
python3 tools/psf_decode.py landmarks Landmark.psf \
  --format geojson --pretty --output landmarks.geojson
```

## Potvrđeni lokalni rezultati

| Sloj | LZMA streamovi | Kompresovano | Raspakovano | Status indeksa |
|---|---:|---:|---:|---|
| Basic | 65.527 | 44.487.407 B | 82.275.083 B | kompletan stream layout: 9.051 klaster; 26.056 primary + 689 CombinedDesc + 1.590 finalizer-directory payload-a |
| ADAS | 3.336 | 29.203.579 B | 43.909.574 B | kompletan, 5 grupa |
| AdvancedRouting | 3.342 | 3.491.195 B | 5.869.644 B | kompletan, 10 grupa |
| GlobalPOIIndices | 7.069 | 6.158.795 B | 11.650.848 B | kompletan stream layout: 522 klastera; semantika zapisa u radu |
| Landmark | 72 | 11.347 B | 12.036 B | kompletan; 78 Landmark zapisa |
| MIB2 AdvancedMap2D | 12.721 | 8.182.261 B | 17.856.616 B | dva lanca; srednji indeks u radu |

Landmark koordinate su u Web Mercator metrima; WGS84 konverzija je proverena
na stvarnim lokacijama kao što su Manastir Savina i Gospa od Škrpjela.

## QNX6 čitač

`tools/qnx6_extract.py` je userspace, read-only čitač bez dodatnih paketa.
Podržava standardni QNX6 i stari Audi MMI3G raspored superbloka.

```bash
python3 tools/qnx6_extract.py info app.img
python3 tools/qnx6_extract.py ls app.img /navigation
python3 tools/qnx6_extract.py extract app.img /navigation -o navigation
python3 tools/qnx6_extract.py cat app.img /navigation/PSFVersion.txt
```

Ekstrakcija ne pravi aktivne simboličke linkove iz nepouzdanog firmware-a;
njihove mete čuva kao obične `*.symlink` fajlove.

## Testovi

Integracioni testovi koriste lokalno raspakovani firmware i Serbia mapu kada
su prisutni. Pedeset tri testa proveravaju QNX6 geometriju, hash parsera i
bezbedan izlaz bez praćenja symlinkova, sve zlib CINFO prozore, PSF
potpise/hash delove, 283 metadata zapisa, sve potvrđene Basic indeksne
familije, punih 65.527 Basic i 7.069 GlobalPOI streamova, svih 72 Landmark
LZMA klastera, 78 semantičkih Landmark objekata i kompletan Basic
node/edge/topology/normalized-geometry/handle2-text/name-language prolaz.

```bash
python3 -m unittest discover -s tests -v
```

Detaljni offseti i dokazi su u [`docs/PSF60_FORMAT.md`](PSF60_FORMAT.md),
a firmware, mapa, M.I.B/offload paket i prethodni Claude rad popisani su u
[`docs/INPUT_INVENTORY.md`](INPUT_INVENTORY.md).
