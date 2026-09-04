# MIB → MMI 3G Plus implementation status

Poslednje ažuriranje: 2026-09-03. Status se menja tek kada puna skripta,
korpusna provera i testovi potvrde stavku.

**STANJE: konverzija MIB → 3G+ je kompletna.** Pun Serbia dataset (838.433
ivice) prošao je ceo lanac do gotovog `SRB.5_1.0.ATLAS` (32,3 MB), koji prolazi
sve verifikatore. Manifest: `out/conversion_manifest/manifest.json`. Model
zaštite je dokumentovan u `docs/FW_PROTECTION_MODEL.md`; prihvatanje na uređaju
zahteva izdavačev potpis paketa.

## Redosled rada

1. **Završeno — jezici, transliteracija i name source ugovor.**
   `30=Bosnian`, `31=Albanian`, `33=Serbian`, `48=Montenegrin` dokazani su
   iz Basic `worldCountry` official-language listi i regionalnih cross-check
   mapa. Svih 271.823 fizičkih stavki prolazi grupisanje u 151.818 logičkih
   imena; svih 120.005 alternate zapisa je validan base→transliteration par.
   Firmware VA `0x012a97e0` je implementiran kao eksplicitna consumer lista
   jezičkih ID-jeva za transliteraciju. Nema izmišljenog globalnog ranga
   različitih jezika ili aliasa.
2. **Delimično završeno — road atributi.** Puna skripta potvrđuje svih 838.433
   edge-a i 903.487 geometry dela bez parse greške. Implementirani su statički
   A→B/B→A smer, tag 1 simple speed, tag 13 node-A/node-B broj traka, tagovi
   14/15 passing restriction, field-level tag 16 `LANES` i 13-bitni automotive
   mask. Dynamic topology direktorijum je sada kompletno parsiran: 868 klastera,
   1.178 typed payloada, svih 3.324 markera i 1.819 firmware-dekodiranih type-5
   edge slogova. Svih 42 type-3 tabela je edge-mapirano u 308 selector slogova
   i 56 deljenih condition objekata; direction/query selektori i polja godine,
   meseca, dana, weekday maske i 15-minutnog intervala su dekodirani sa
   evaluatorom. Geometry tag 2 daje 61.618 extended-speed vrednosti na 23.844
   edge-a, uključujući subtype-7 condition parove; subtype 0 je dokazani
   `SLT_GENERAL`. Još čekaju runtime timezone/query-mask povezivanje, potvrda
   speed jedinice i preostalih extended-speed subtype naziva i vehicle-class
   značenja automotive bitova. Tag 16 je sada kompletno razdvojen u 39.538
   lane slogova; sva firmware-consumed polja i category maske 0/1/4/5/32/33/128
   su izvezene, dok javna enum imena ostaju otvorena. Automotive mask je
   razdvojen u `active_bit_indices` na svakom edge-u i corpus bit-count profil;
   javna imena bitova ostaju otvorena. Edge `Urban` je sada zasebno dokazano
   polje: VA `0x002f0484` radi OR geometry-part secondary bit-a 5 (`0x20`) i
   upisuje rezultat u edge objekat `+0x16c`, koji Urban Entry/Exit consumer na
   VA `0x013e5be8` direktno čita. Puni MIB profil daje 448.174 urban edge-a od
   838.433. Type-5 javno ime/jedinica nisu izmišljeni.
3. **Strukturno završeno — AdvancedRouting; semantika otvorena.** Svih 3.342
   streamova i 839.501 recorda lossless je parsirano. Za Basic je vezano
   838.313 recorda, 120 edge-a nema taj sloj, a sedam supra klastera čuva
   1.188 dodatnih recorda. Manevar/restriction tagovi još nisu imenovani.
4. **Strukturno završeno — ADAS; semantika otvorena.** Svih 3.336 klastera i
   838.433 recorda parsirano je i povezano sa Basic edge-om 1:1. Firmware
   potvrđuje spajanje Base/Complete/ADAS containera i zasebne scalar/profile
   consumere; javna imena internih attribute ID-jeva ostaju otvorena.
5. **Završeno — Orion clothoid source adaptacija.** Svih 838.433 edge-a i
   3.895.681 tačka je provereno; 3.057.085 non-zero krakova izvezeno je kao
   validni `kappa=0`, `dkappa=0` clothoid segmenti, endpoint greška 0.0.
   Tangent continuity na originalnim uglovima se ne tvrdi.
6. **Ciljna Orion schema i code-1 column layout su dokazani; reference/indeksi
   čekaju.** Read-only puni profil originalnog 3G Plus `PSD3` prošao je svih
   43.402 blokova i 842.777.616 bajtova (`file_coverage=1.0`), uspešno raspakovao
   42.081 deo i našao 2.270 imena. Svih 835 LZMA neuspeha pripada blokovima
   imena `CONTAINER`; nisu menjani ulazni fajlovi. Strogi parser sada egzaktno
   povezuje svih **42.066** logičkih šema, descriptor tabela, codec nizova,
   `data_offset` i `payload_size`; svih **649.210** column codec bajtova je `1`.
   Svih 42.066 payload-a ima delta 0 i prolazi split→assemble proveru identično
   bajt-po-bajt. Ranijih 17 fallback tabela objašnjeno je 12-bajtnim `kind 3`
   indirektnim deskriptorom. Na punom fajlu postoji 20.250 takvih delova: svaki
   ima tačno jednog skrivenog logical-member kandidata i svaki ispunjava
   `size = ceil(count × storage_bits / 8)`. Svih 42.066 tabela sada je potpuno
   grupisano do `(composite, member, part_index)`, uključujući Map i VidTable
   optional pravila. Schema, descriptor tabela, payload i ceo decoded chunk
   ponovo se serijalizuju identično bajt-po-bajt u svih 42.066 slučajeva.
7. **Jedinstveni decoded topology/centerline graph writer je završen; property
   i ATLAS sloj čekaju.** `tools/orion_object_writer.py` uzima MIB graph `nodes.jsonl`,
   deterministički prevodi WGS84 u signed `degree × 10^7`, generiše novu Orion
   `Map/PointLlh` logičku šemu, tri fizičke `0x35` code-1 kolone, descriptor
   tabelu i codec niz. Izlaz se obavezno ponovo parsira i proverava schema,
   tabela, member grouping, vrednosti, payload size i ceo decoded chunk. Lokalni
   uzorak svih 100 dostupnih node redova daje 1.303 B, 100/100 vrednosti po
   koloni i sve interne provere `true`. To je stvarni novi decoded object
   payload, ali još nije ATLAS blok niti rutabilna baza. Header reči 2..4 ostaju nula dok se
   ne dokaže njihova runtime semantika. `tools/orion_schema_extract.py` je
   zatim iz originalnog PSD3 bloka `0x1000` automatski izvukao zajedničku graph
   šemu: class instance handle-i kreću od 1 i sabiraju se schema redosledom;
   originalni `EdgeRoadElement.From/To` su codec-1 `0x24` direktne reference u
   `NodeRoadElement` opseg `1573..1955`, uz `0` sentinel za eksterni objekat.
   Novi writer isto pravilo primenjuje na MIB source. Naknadna potpuna fizička
   analiza ispravila je grupisanje: `EdgeRoadElement.Attributes` je implicitna
   1:1 struktura bez serialized dela. Sledeća kolona ima 383 jedinstvene
   vrednosti i tačna je permutacija kompletnog PointGeometry handle opsega
   `30..412`, pa pripada `NodeRoadElement.PointGeometry`. Tek narednih 383
   četvorobitnih cardinality vrednosti sabira se na 1.094, a sledećih 1.094
   `uint16` vrednosti sve su Edge handle-i; ta dva dela, uz optional/default,
   pripadaju članu `Vias`.
   Integrisani sample zato sada u jednom chunku pravi PointGeometry `1..100`,
   Edge `101..200`, Node `201..300`, direktne `From/To` reference i 76 lokalnih
   `Vias` incidencija. Binary ima 2.198 B i svih 12 schema/table/value/range/
   incidence self-checkova prolazi. Puni originalni PSD3 corpus je posle ove
   korekcije ponovo validiran: svih 42.066 schema/tabela/payload/chunk roundtrip
   provera ostaje bajt-identično. `tools/orion_centerline_writer.py` zatvara
   sledeći samostalni decoded sloj iz pripremljenog clothoid source-a. Da se ne
   izmisli tangent continuity, svaki izvorni pravolinijski segment postaje jedan
   `ClothoidCenterlineGeometryPart` sa dve `PointLld` pozicije i istim smerom na
   oba kraja. Sample od 100 edge-ova daje 824 part-a, 1.648 PointLld redova i
   17.255 B; direktni `EdgeRoadElement.CenterlineGeometry` handle-i i svih deset
   schema/table/value/range/geometrijskih provera prolaze. `Direction` se piše
   kao originalni fizički `u16` full-circle tip; konačna device interpretacija
   ugla ostaje za validaciju. `tools/orion_merged_graph_writer.py` zatim strogo
   poravnava graph i clothoid source po edge ID-u i spaja sve u jedan globalni
   handle prostor. `tools/orion_property_layout_profile.py` dodatno dokazuje
   property container ugovor na originalu: 580 `Attributes.Parts` cardinality
   vrednosti razvija se u 586 `PropertyD1` lista, a njihove cardinality vrednosti
   3–4 daju tačno 1.760 globalnih Property handle-a. Svi handle-i pripadaju
   opsezima Adas/AudiUrban/SpeedLimit/Urban podklasa; svih sedam provera prolazi.
   `tools/orion_property_corpus_profile.py` je zatim prošao svih 43.402 bloka:
   među 42.081 decoded chunkom pronašao je 8.081 graph/property chunk sa
   1.445.496 edge-eva, 1.511.928 lista i 4.801.622 potpuno klasifikovana
   property handle-a. Tačno 1.511.916 lista sadrži obavezni redosled
   Adas→Urban→AudiUrban, dok 12 specijalnih lista sadrži SpeedLimit→SpeedLimitSign.
   Merged writer emituje po jedan Adas i AudiUrban objekat, dva Urban objekta
   sa vrednostima 0/1 i tri handle-a po edge-u; Urban handle sada se bira iz
   firmware-potvrđenog MIB source polja. Adas/AudiUrban ostaju eksplicitne nule,
   pri čemu je AudiUrban označen kao konzervativni fallback. Dodatni scalar prolaz je bez greške dekodirao
   4.333 chunkova koji imaju samo tri bazne klase: `Adas.Compliant` je 0 u svih
   4.333 class redova i svih 283.228 referenci; `UrbanProperty` reference biraju
   0/1 u odnosu 124.701/158.527, a `AudiUrbanProperty` 126.965/156.263. Egzaktni
   referencirani trojci su `0+0+0=124.701`, `0+1+0=2.264` i
   `0+1+1=156.263`: u ovom baseline-only skupu AudiUrban je strogi podskup
   Urban-a. Adas nula i MIB Urban
   sada su zatvoreni; AudiUrban source mapiranje još nije dokazano. Sample binary
   ima 19.849 B: Adas `1`, AudiUrban `2`, Urban `3..4`, PointGeometry `5..104`,
   Clothoid `105..204`, Edge `205..304`, Node `305..404`,
   824 centerline part-a, 1.648 PointLld redova i 76 Vias referenci. Svih 21
   provera schema/table/payload/property/ID-alignment/handle-range/topologije/
   geometrije prolazi. Pre semantičkog zatvaranja stavke 2 ostaju AudiUrban
   mapiranje i opcione speed/lane/restriction klase; zatim slede catalog/container
   indeksi, apsolutni offseti, kompresija i repack.

## Izvršni dokaz za pre-writer slojeve

### Checkpoint za nastavak — 2026-09-02

Stavka 2 je napredovala preko konzervativnog baseline-a: full-corpus Property
profiler je završen, tri obavezne klase i njihovi handle-i se pišu, a kanonski
chunk prolazi svih 21 self-checkova. Adas nula je potvrđena na 4.333 čista
originalna chunk-a. Obični Urban je 1:1 vezan za geometry secondary bit 5 i
upisan u writer kao 0/1 izbor; AudiUrban još nije vezan jer susedni MIB bitovi
ne zadovoljavaju dokazani subset ugovor. Prvi sledeći posao je dokazati samo
AudiUrban source mapiranje, zatim dodati
opcione `SpeedLimit`, `NumberOfLanes`, `PassingRestriction` i `SpeedBumps`
objekte. Stavka 3 (catalog/container indeksi) nije započeta.

### AudiUrban kandidat — korigovani checkpoint, 2026-09-03

Lokalni firmware prolaz je suzio AudiUrban istragu na konkretan, ali još
neimenovan kandidat. `FUN_002f0484` radi OR geometry-part secondary bit-a 6
(`0x40`) preko svih delova edge-a i upisuje rezultat na decode output
`+0x1e9`. Pozivalac `FUN_013bcc28` direktno dokazuje da je decode-output baza
fizički cached-edge objekat `+4`, pa je taj bajt fizički na `+0x1ed`.

Raniji opis da `FUN_010eec88` i `FUN_010f2b68` prenose ovaj bajt u
"route-edge `+0x281`" bio je pogrešan. String/call trag sada dokazuje da su to
`OnBGeoPOIService::Start` i `OnBGeoPOIService::UpdateResults`; `+0x281` je
polje njihovog radnog stanja. To je samo bulk kopija odgovora i nije
AudiUrban consumer.

Puni sken opsega `0x00800000..0x01450000` obradio je 26.095 funkcija. Prvi
sken tri cached/decode offseta dao je 303 široka pogotka, ali samo deset
headera sadrži bit-6 offset. Četvoroprocesni sken `+0x281/+0x285` nije našao
semantičkog čitaoca u GeoPOI objektu. Novi egzaktni sken celog definisanog
firmware prostora (`0x00010000..0x01450000`) obradio je 44.531 funkciju za
`+0x1e9/+0x1ed`; u relevantnom navigation delu rezultat se svodi na decoder,
zero-init/copy puteve i pomenutu GeoPOI bulk kopiju. Primarni cached-edge
vtable takođe nema getter: stvarna tabela na `0x01710798` ima samo dve
destruktorske stavke, dok su naredni slotovi susedne male tabele.

Semantički consumer ili naziv koji bi secondary bit 6 vezao baš za
`AudiUrbanProperty` još nije pronađen. Pored toga, sirovi bit 6 sam ne poštuje
originalni ugovor `AudiUrban=1 => Urban=1`, pa writer ispravno ostaje na
konzervativnoj AudiUrban nuli.

Tačna naredna tačka više nije GeoPOI `+0x281`. Treba pratiti puni cached-edge
objekat kroz kopije/interfejse ili prostorno upariti iste puteve između MIB i
originalnog 3G+ korpusa, iz toga izvesti kompletnu AudiUrban formulu i tek
onda pokrenuti puni subset invariant. Tek posle oba dokaza AudiUrban sme u
writer. Mašinski checkpoint je u
`out/firmware_re/audiurban_candidate_phase/report.json`, a paralelni runner
je `tools/run_ghidra_sharded_grep.py`.

Prostorni put je sada praktično otvoren. Novi read-only
`tools/orion_graph_spatial_probe.py` dekodira originalne signed
`PointLlh.Longitude/Latitude` kolone (`degree × 10^7`), skenira zadati bbox,
podržava resume preko `--start-offset` i po izboru čuva samo pogođene decoded
chunkove i njihove šeme. Tri PSD particije su time razgraničene; Balkan je u
`PSD/APN221EU22093P1664a.5_1.0.ATLAS`. Od resume offseta `0x7a279160` samo 203
bloka su dala osam pogodaka na području Crne Gore. Svih osam sačuvanih šema
sadrži edge/node geometriju i `AudiUrbanProperty` (4–24 reda po chunku), pa je
sledeći konkretan posao rekonstruisati per-edge property trojku i upariti
centerline sa MIB grafom. Artefakti i checksumovi su u
`out/orion_graph_spatial_probe_serbia_02/`.

Per-edge Property rekonstrukcija je sada izvršna u
`tools/orion_edge_property_decode.py`. Nad osam sačuvanih chunkova dekodirano
je svih 1.593 edge-a i njihovih 1.795 referenciranih `PropertyD1` lista;
nijedan edge nije ostao bez Adas/Urban/AudiUrban trojke. Skripta razdvaja
baseline-only fizički prozor od opcionih Property šema, čuva lossless vrednost
svake part-liste i računa efektivni edge OR. U opcionom prostornom uzorku 72
edge-a imaju efektivni `AudiUrban=1, Urban=0`, pa raniji subset dokaz ne treba
generalizovati van 4.333 baseline-only chunkova. Izlaz je u
`out/orion_edge_properties_montenegro/`; svih 113 testova i oba skupa
checksumova prolaze. Sledeće je vezati ove edge redove za From/To/centerline.

Taj topology spoj je sada završen kroz
`tools/orion_edge_geometry_decode.py`. Za svih 1.593 originalnih edge redova
dekodirani su direktni `From`, `To` i `CenterlineGeometry` handle-i; lokalni
endpoint-i su razrešeni kroz `NodeRoadElement.PointGeometry` do signed
`PointLlh` koordinata, a zatim 1:1 spojeni sa prethodno rekonstruisanim
Property listama. Svih 1.260 node→point handle-a po chunkovima čine potpune
permutacije, svi nenulti endpoint-i su u Node opsegu i svih 1.593 centerline
referenci pripada `ClothoidCenterlineGeometry`. Zabeležena su 152 nulta
endpoint sentinela za veze van lokalnog chunka. Potpisani lossless edge source
je u `out/orion_edge_source_montenegro/`; svih 113 testova prolazi. Sledeća
granica je dekodiranje `ClothoidCenterlineGeometry.Parts` i `PointLld`, pa
prostorni join tih polilinija sa MIB edge-ovima.

Centerline payload i prvi cross-version join su sada automatizovani.
`tools/orion_centerline_geometry_decode.py` koristi lokalni process pool i
lossless razvija `ClothoidCenterlineGeometry.Parts ->
ClothoidCenterlineGeometryPart.Positions -> PointLld`, uz stvarnu permutaciju
centerline handle-a (originalni edge i centerline redosled nisu isti). Prvi
uzorak ima 1.593 edge-a, 1.610 part-a i 10.293 PointLld reda; prošireni
unutrašnji uzorak ima 64 chunka, 21.570 edge-a, 21.642 part-a i 110.965 PointLld
redova. Sve cardinality, handle, coordinate i endpoint provere prolaze.

`tools/mib_graph_spatial_extract.py` je u osam procesa pregledao svih 838.433
MIB edge-a i izdvojio 64.274 kandidata u odgovarajućem bbox-u.
`tools/orion_mib_spatial_match.py` čuva stroge 1:1 kandidate, dok
`tools/orion_mib_corridor_match.py` podržava realni 1:N slučaj različite
segmentacije. U unutrašnjem uzorku corridor prag prolazi 148 high i 643 medium
parova. Negativni rezultat je jasan: MIB geometry secondary bit 6 nije
AudiUrban formula; među high parovima sa originalnim AudiUrban=1 bit6 je 0 u
97, a 1 u samo 14 slučajeva. Ni Urban između dve generacije nije identičan
objektni marker, pa se korelacija za sada tretira kao kandidat, ne identity
dokaz. Izlazi su u `out/orion_*montenegro_04/` i
`out/mib_graph_spatial_montenegro_03/`. Sledeće je poboljšati cross-version
matching topološkim lancima i atributima, bez spuštanja geometrijskih pragova.
`tools/audiurban_spatial_feature_profile.py` je dodatno proverio svih osam
secondary bitova na 148 high-confidence redova. Nijedan bit nije direktna
AudiUrban formula; najbolji pojedinačni kandidat je bit 5 sa samo 56,46%
slaganja, dok bit 6 ima 31,69%. Ovaj rezultat zatvara potragu za prostim
jednobitnim preslikavanjem na ovom korpusu.

Prvi topološki filter je implementiran u
`tools/orion_mib_topology_chain.py`. Od 791 high/medium corridor kandidata on
zadržava samo povezane MIB komponente bez grananja, orijentiše svaki edge po
`from/to` čvorovima, spaja poliliniju i ponovo meri kompletnu geometriju. Samo
6 lanaca prolazi high i 20 medium prag; prihvaćeni slučajevi imaju 1–5 MIB
edge-ova po jednom originalnom edge-u. Preostalih 765 je ispravno ostavljeno
nepotvrđeno. Ovaj prvi filter pokazuje da corridor lista često ne sadrži sve
kratke spojne edge-ove. Sledeći korak je ograničena graph-search varijanta koja
traži nedostajuće veze između MIB čvorova, uz strogi geometrijski koridor.

Ta bounded varijanta je sada izvršna u
`tools/orion_mib_bounded_graph_match.py`: bira MIB čvorove blizu oba
originalna endpoint-a, traži do 12 hopova samo kroz edge-ove unutar koridora i
ponovo meri celu putanju. Sa 80 m potvrđuje 8 high + 50 medium putanja, do šest
MIB edge-ova. Kontrolnih 120 m daje identičnih 8+50 i samo više low rezultata,
pa širenje koridora nije rešenje. U 58 prihvaćenih putanja originalni
AudiUrban=1 ima MIB bit6=0 u 35/36 slučajeva, što dodatno odbacuje bit6
hipotezu. Sledeće treba dodati stabilne direction/road-class/name atribute u
score, ne popuštati geometrijske pragove.

MIB prostorni ekstrakt sada uz geometriju čuva potvrđeni travel direction,
automotive mask, speed tagove i lane/passing prisustvo.
`tools/orion_mib_stable_attribute_profile.py` ih poredi samo na 58 prihvaćenih
bounded putanja. Lane presence daje 96,55%, ali samo na dominantno negativnim
primerima (56 `0->0`, 2 `1->0`), pa nije pozitivan identity signal. Passing
daje 87,93%, speed samo 56,90%. Automotive bit 8 je najbolji pojedinačni
AudiUrban kandidat sa 70,69%, ali je nedovoljan i nema samostalni firmware
dokaz. Nijedan od ovih signala zato još nije dodat u matcher. Sledeća granica
je dekodiranje stvarnih vrednosti originalnih SpeedLimit,
NumberOfLanes/PassingRestriction objekata, umesto poređenja samog prisustva.

Ta granica je sada zatvorena u `tools/orion_edge_property_decode.py`. Skripta
automatski poravnava kompletan logički redosled Property podklasa sa fizičkim
kolonama, dozvoljava samo writer-ovo dokazano sužavanje unsigned širine i
zahteva sva tri poznata Adas/AudiUrban/Urban sidra. `kind-3` fizički descriptor
se razmotava preko anonimne indeksne kolone (`dictionary[index[row]]`), a
row-aligned `SpeedLimit.Time` čuva oba sirova `TimeDomain` dela. Svih 64/64
chunk-a i 21.570 edge redova prolazi: dekodirano je 748 SpeedLimit, 390
NumberOfLanes, 263 PassingRestriction i 54 SpeedBumps objekta, uz tri stvarne
indirect-dictionary kolone. Lossless rezultat i descriptor provenance su u
`out/orion_edge_properties_montenegro_04/`. Brojevi su source vrednosti; enum
nazivi i jedinice se ne pretpostavljaju bez firmware dokaza. Sledeće je
atributsko poređenje ovih vrednosti sa MIB putanjama i merenje da li popravljaju
jednoznačnost bounded matchera.

Value-level poređenje je završeno u
`tools/orion_mib_property_value_profile.py`, a MIB ekstraktor sada čuva i
stvarne simple/extended speed, `NumberOfLanes` endpoint vrednosti i
simple/extended passing detalje. Ponovni puni MIB prolaz je pregledao svih
838.433 edge-a u osam procesa. Na 58 bounded putanja speed postoji na obe
strane samo jednom i taj skup nije jednak; lane i passing nemaju nijedan par
sa vrednošću na obe strane. Čak među osam geometry-high putanja tri imaju speed
samo na jednoj strani. Ovo nije signal za jači score: pokazuje da geometry
high/medium još nije dokaz semantički identičnog road segmenta, ili da su se
atributi promenili između godišta. Artefakt je
`out/orion_mib_property_values_montenegro_04/`. Sledeće mora razdvojiti te dve
mogućnosti kroz širi, stabilniji originalni uzorak i topology/name/direction
identitet pre nego što se uvede hard attribute filter.

Širenje je automatizovano jednim runnerom,
`tools/run_orion_cross_version_corpus.py`, koji od resume offseta izvršava
probe → Property → endpoint topology → centerline → corridor → bounded →
value/direction profile i prenosi live izlaz svakog procesa. Corpus 05 dodaje
64 chunk-a, 20.369 edge-a i 90.409 PointLld redova; corpus 06 dodaje 128
chunkova, 31.740 edge-a i 309.762 PointLld redova. Sa corpusom 04 ukupan
provereni uzorak sada ima 256 chunkova, 73.679 originalnih edge-a i 511.136
PointLld redova. MIB prozor je jednom proširen na 149.105 kandidata i ponovo
proveren preko svih 838.433 edge-a.

Nezavisni bounded rezultati su 1 high + 6 medium za corpus 05 i 1 high + 8
medium za corpus 06; zbir sva tri corpusa je 10 high + 64 medium. Novi
`tools/orion_mib_direction_profile.py` rekonstruiše jedini node-povezan
redosled/smer čak i kada JSON edge ID lista dođe obrnuto. Od 74 prihvaćene
putanje 66 je MIB-dvosmerno, 6 closed i 2 reverse. Raw Orion Orientation
vrednosti su previše retke i iste vrednosti se pojavljuju uz različite MIB
modove; novi corpusi takođe ne daju novi both-present speed/lane/passing par.
Zaključak ostaje strog: ni direction ni opcioni atributi još nisu identity
signal, a naredna korisna granica je name/road-class identitet ili referentni
put za koji ručno znamo da je isti u oba godišta.

Prva identity podfaza je završena skriptom
`tools/orion_item_identifier_profile.py`. `Item.Identifiers` je potvrđen kao
tačno jedan sirovi 64-bitni red za svaki class-ordered `Item` potomak: 134.581
redova u 256 chunkova, od toga 73.679 za `EdgeRoadElement`. Ima 130.929
jedinstvenih vrednosti i 3.533 vrednosti koje se ponavljaju između chunkova;
nema ponavljanja unutar istog chunka. Međutim, svih 3.780 parnih poređenja
ponovljenih edge identifikatora imaju različitu geometriju (3.403 para imaju
najbliže krajeve unutar 10 m). Zato ovo polje nije jedinstveni edge/object ID
i ne sme se koristiti kao topology join ključ. Sačuvani su puni `u64`, low i
high delovi u `out/orion_item_identifiers_montenegro_04_06/`; moguća semantika
road-group/name reference ostaje otvorena. Sledeća podfaza je korelacija ovih
ponovljenih ključeva sa MIB imenima/road klasama.

Ta podfaza je sada završena lokalno. `mib_graph_spatial_extract.py` schema-v3
u jednom 8-worker prolazu dekodira i direct handle-2 logička imena, njihovu
normalizovanu base/transliteration uniju i lokalni firmware-backed endpoint
class nibble. Pregledano je svih 838.433 MIB edge-a; bbox corpus ima 149.105
edge-a, od kojih 67.068 ima ime, uz 91.835 normalizovanih name referenci i
274.373 lokalno razrešena endpoint class polja. External endpoint class ostaje
`null`, a javni enum nazivi nisu izmišljeni.

`tools/orion_mib_name_identity_profile.py` je spojio 1.110 high/medium corridor
redova iz sva tri originalna corpusa sa novim MIB semantičkim slojem. U uzorku
postoje 23 para sa ponovljenim `Item.Identifiers`: name skupovi su 13 puta
jednaki, 4 puta se preklapaju i 6 puta nedostaju; endpoint class je 18 puta
jednak, 4 puta se preklapa i jednom nedostaje. Nema kontradiktornog/disjoint
name para. Ipak, svih 23 para dele najmanje jedan isti MIB edge (10 jednakih i
13 preklapajućih skupova kandidata), pa ovo nije nezavisan dokaz name-key
semantike. Dokazan je koristan cross-chunk lokalni grouping signal, ali i dalje
ne jedinstveni edge ID. Izlazi su `out/mib_graph_spatial_montenegro_names_06/`
i `out/orion_mib_name_identity_montenegro_04_06/`.

Originalni Orion name/road-class sloj je zatim tražen bez heurističkog string
scan zaključka. Novi `tools/orion_schema_name_inventory.py` paralelno indeksira
ceo ATLAS, dekodira kompresovane šeme i podržava direktni CTY legacy variant
bez member annotations. Rezultati:

- PSD0: 104.432 graph `Map` šeme (+ jedan `Root`), bez road name/class člana;
- PSD1: 106.852 graph `Map` šeme, bez road name/class člana;
- PSD3: 8.081 graph `Map` + 33.985 `VidTable` šema, bez takvog graph člana;
- CTY0: 213.041 `Map` šema za `Building`/`Material`/`VertexArray` 3D model,
  ne za road semantiku.

Inventari su u `out/orion_schema_name_inventory*`. GDB/GD2 i LIT/LI* ostaju
odvojeni legacy subsystem (`GDB` počinje `deadbeef`, `LIT` sa `FLDB`); konkretni
poznati nazivi nisu pronađeni kao plaintext, što nije dokaz da ih nema u
kodiranim/kompresovanim zapisima.

Ključni bridge test je kompletiran skriptom
`tools/orion_vidtable_identifier_profile.py`. Ona čita fizički type `0x26` kao
pun raw little-endian `u64`, a ne kroz generički low-32 prikaz. Nad svih 43.402
PSD3 blokova pronađeno je 33.985 VidTable tabela sa 94.974.728 AtlasIds
dictionary reda. Egzaktno poklapanje svih 64 bita postoji za 65.841/130.929
jedinstvenih Item identifikatora i obuhvata 69.253/134.581 Item reda; svi
pogođeni redovi su `EdgeRoadElement`. U VidTable-u se ti ID-evi pojavljuju
76.457 puta. Ovo dokazuje zajednički ID domen `Item.Identifiers` ↔
`VidTable.AtlasIds`, ali još ne dekodira row-to-dictionary odnos ni vezu sa
`XacVectorOffsets`. Dokaz je u
`out/orion_vidtable_identifier_profile_montenegro_04_06/`.

Tačna sledeća granica je: rekonstruisati optional/indirect VidTable redove,
upariti `AtlasIds` sa `XacVectorOffsets`, pa proveriti format ciljnog XAC
vektora i tek potom pratiti naziv/road-class prema legacy store-u. GDB/LIT se
ne smeju unapred proglasiti direktnim ciljem bez tog offset dokaza.

Prvi deo te granice je sada zatvoren. `tools/orion_vidtable_row_mapping.py`
dekodira oba fizička oblika: direct AtlasIds niz i tag-3 dictionary sa
eksplicitnom anonimnom indeksnom kolonom. Puni 8-worker prolaz daje 13.871
direct + 20.114 indirect VidTable tabela i 170.571.814 ekspandiranih,
indeksno poravnatih `AtlasId → XacVectorOffset` redova. Za svaki chunk su
strogo provereni jednaki vector countovi, dictionary cardinality, svi index
opsezi, konačna dužina i jedinstvenost XAC offseta unutar tabele. Svih 33.985
tabela prolazi. Među zadatih 130.929 Item ID-eva, istih ranije dokazanih 65.841
ima ukupno 299.486 ekspandiranih redova. Kompletan table profil i izdvojeni
relevantni redovi, sa checksumovima, nalaze se u
`out/orion_vidtable_row_mapping_montenegro_04_06/`.

Sledeći mali korak je završen u `tools/orion_xac_vector_bind.py`. Parser je
pročitao sva tri FLDB sharda i fizički, ne samo kroz imenovane `.xac` entry-je,
našao 47.176 `VEKTORBLOCK` markera. Svih 33.985 VidTable countova čini strogo
uređen podniz fizičkih XAC countova; svi izabrani parovi imaju jednak count i
svi lokalni maksimalni offseti su ispod konzervativne granice narednog
markera ili kraja vlasničke FLDB stavke. Od toga je 33.923 fizičkih pozicija
jednoznačno određeno count+order dokazom. Kod 62 VidTable tabele ponovljeni
count dopušta ukupno 147 kandidata; oba kraja i svi kandidati sačuvani su u
`out/orion_xac_vector_binding/`, pa nisu predstavljeni kao dokazano
jednoznačni.

Dokazan namespace je lokalni pridruženi XAC vector block. BE size polje na
markeru nije samo po sebi kraj adresnog prostora: 3.500 tabela ima maksimalni
offset iznad tog polja, iako svih 33.985 prolazi fizičku granicu.

Unutrašnja byte-baza i record start sada su dokazani direktno iz NavCore XAC
lookup-a i automatizovani u `tools/orion_xac_vector_offset_resolve.py`.
Version <=4/direct target je `marker + offset`. Kada je version >4 i BE16
`+0x72 == 1`, BE32 `+0x6c` daje index tabelu, BE16 `+0x70` njen broj ulaza, a
target je `marker + 2*BE16(index_table + offset)`; indexed offset mora biti
paran. Puni 8-worker prolaz proverava svih 170.571.814 VidTable vrednosti:
9.648 tabela je direct, 24.337 indexed, nema out-of-range targeta i svaki
razrešeni zapis ima `first_byte & 0xc0 == 0xc0`, isti uslov koji firmware
koristi za vector record.

Formula je strukturno razrešila 41/62 prethodno dvosmislene fizičke veze.
Svih 33.929 već jednoznačnih named-XAC veza pripada `_2.xac` porodici, bez
jednog `_1.xac` izuzetka; taj provereni owner invariant razrešava 19, a strogi
globalni red poslednja 2 slučaja. Konačno stanje je 33.985/33.985 jedinstvenih
fizičkih bindinga i nula unresolved. U
`out/orion_xac_vector_offset_resolution/selected_item_targets.jsonl` je
299.486 relevantnih Item redova već prevedeno na konkretan DB, apsolutni i
relativni XAC target i 16-bajtni prefix. Sledeća granica je semantički parser
samog `0xc0` vector recorda, ne više adresiranje.

### XAC vector record grammar i name-reference checkpoint — 2026-09-03

Ta granica je sada pređena, ali samo do reference nivoa. Puni lokalni prolaz
nad svih **299.486** `selected_item_targets` radi sa dva odvojena mmap ulaza:
XAC baza daje record bajtove, a NavCore daje descriptor tabelu. Ovo ispravlja
raniju eksperimentalnu grešku: descriptor ne sme da se čita iz XAC mmap-a;
stari cursor/length zaključci iz te varijante nisu semantički dokaz i zadržani
su samo kao dijagnostički artefakti.

Firmware-backed parser u `tools/orion_xac_vector_record_layout.py` i njegovim
pratećim alatima potvrđuje sledeće:

1. target je vector record kada `b0 & 0xc0 == 0xc0`;
2. 11-bitni key je `((b2 & 7) << 8) | b3`; bit 3 u `b2` bira
   backreference, čiji je distance `key * 2 + 2`;
3. key indeksira četvorobajtni NavCore descriptor na VA `0x085b4fe8`;
   descriptor/runtime flagovi određuju opcione bajtove i početak eventualnog
   name-reference nastavka;
4. svih 299.486 recorda je obrađeno u 96 grupa sa 8 radnika, bez parse
   greške.

`tools/orion_xac_vector_name_refs.py` je zatim za recorde sa name flagom
dekodirao packed 14-bitni reference niz, sa firmware continuation pravilom.
Rezultat je 25.110 recorda sa name flagom, 44.722 reference i 8.877 različitih
name ID-jeva; nijedan niz nije unterminated. To još nisu stringovi. NavCore
`FUN_082538e4` i `FUN_082539f0` razrešavaju ID prema `xac_name` objektu, a
`FUN_08253ba0` je cache/decompression decoder name bloka. Potrebno je još
rekonstruisati loader/inicijalizaciju i fizički `xac_name` resource, pa pozvati
ili reprodukovati taj decoder nad realnim podacima. Tek tada se mogu tvrditi
ime, jezik i tip naziva.

Artefakti ovog checkpoint-a:

- `tools/orion_xac_vector_record_layout.py`;
- `tools/orion_xac_vector_payload_probe.py`;
- `tools/orion_xac_payload_layout_infer.py`;
- `tools/orion_xac_vector_branch_profile.py`;
- `tools/orion_xac_vector_branch_select.py`;
- `tools/orion_xac_vector_name_refs.py`;
- `tools/orion_stage_watcher.py` i `tools/orion_xac_pipeline.json` za
  ponovljiv sekvencijalni lokalni pipeline;
- `out/orion_xac_vector_record_layout/`,
  `out/orion_xac_vector_name_refs/` i
  `out/firmware_re/orion_xac_bridge/`.

Sledeći tehnički korak: iz FLDB/XAC resource direktorijuma povezati stvarni
`xac_name` data blok sa objektom koji očekuje NavCore, zatim napraviti
read-only string/language/type extractor. Ne menjati niti upisivati originalne
ATLAS/XAC fajlove tokom tog rada.

- `tools/basic_world_country_languages.py`
- `tools/basic_handle2_name_profile.py`
- `tools/basic_name_semantics.py`
- `tools/basic_graph_export.py`
- `tools/run_basic_handle2_re.py`
- `tools/run_basic_name_stage.py`
- `tools/run_basic_identifier_crosscheck.py`
- `out/basic_world_country_languages/report.json`
- `out/basic_handle2_name_profile/report.json`
- `out/basic_graph_export/report.json`
- `out/basic_graph_export_latin/report.json`
- `out/firmware_re/basic_handle2/`
- `out/basic_name_stage_latin/report.json`
- `out/basic_identifier_crosscheck/crosscheck_report.json`
- `tools/basic_road_attributes.py`
- `tools/basic_road_attributes_profile.py`
- `tools/basic_dynamic_attributes.py`
- `tools/basic_dynamic_attributes_profile.py`
- `tools/run_basic_road_attributes_re.py`
- `tools/run_basic_urban_semantics_re.py`
- `tools/run_ghidra_sharded_grep.py`
- `tools/run_basic_road_attributes_stage.py`
- `out/firmware_re/basic_road_attributes/`
- `out/firmware_re/basic_urban_semantics/`
- `out/firmware_re/audiurban_candidate_phase/`
- `out/basic_road_attributes_profile/report.json`
- `out/basic_road_attributes_stage/report.json`
- `out/basic_road_attributes_stage/dynamic_attribute_profile/report.json`
- `out/basic_road_attributes_stage/graph_export/edges.jsonl`
- `tools/pre_writer_layers.py`
- `tools/pre_writer_layers_profile.py`
- `tools/pre_writer_layers_export.py`
- `tools/run_pre_writer_layers_re.py`
- `out/pre_writer_layers_profile/`
- `out/pre_writer_layers_source/`
- `out/firmware_re/pre_writer_layers/`
- `tools/orion_clothoid.py`
- `tools/orion_clothoid_export.py`
- `out/orion_clothoid_source/`
- `tools/orion_psd_reference_profile.py`
- `out/orion_psd_reference/`
- `out/orion_psd_reference_full/`
- `tools/orion_column_codec.py`
- `tools/run_orion_column_codec_re.py`
- `out/firmware_re/orion_column_codec/`
- `tools/orion_object_writer.py`
- `tools/orion_centerline_writer.py`
- `tools/orion_merged_graph_writer.py`
- `tools/orion_property_layout_profile.py`
- `tools/orion_property_corpus_profile.py`
- `tools/orion_schema_extract.py`
- `out/orion_point_llh_writer/`
- `out/orion_centerline_writer/`
- `out/orion_merged_graph_writer/`
- `out/orion_property_layout_profile/`
- `out/orion_property_corpus_profile/`
- `out/orion_graph_schema_sample/`
- `tools/run_psd15_profile_re.py`
- `out/firmware_re/psd15_profiles/`
- `tools/orion_schema_name_inventory.py`
- `tools/orion_vidtable_identifier_profile.py`
- `tools/orion_vidtable_row_mapping.py`
- `tools/orion_xac_vector_bind.py`
- `out/orion_schema_name_inventory/`
- `out/orion_schema_name_inventory_psd0/`
- `out/orion_schema_name_inventory_psd1/`
- `out/orion_schema_name_inventory_cty0/`
- `out/orion_vidtable_schema_sample/`
- `out/orion_vidtable_identifier_profile_montenegro_04_06/`
- `out/orion_vidtable_row_mapping_montenegro_04_06/`
- `out/orion_xac_vector_binding/`

Poslednja potvrđena puna test komanda prolazi **132/132** testova (`OK`); uključeni su i
novi legacy-schema, raw-u64, direct/indirect VidTable row-mapping i FLDB/XAC
ordered-binding testovi.
Suite uključuje 21/21
road-attribute unit testova, full-corpus graph schema-v7/type-3/tag-2/tag-16
integraciju, kompletne AdvancedRouting/ADAS cluster corpuse i sintetičku Orion
catalog/column proveru:

```bash
python3 -m unittest discover -s tests -v
```

Ovaj source je upotrebljiv za razvoj `NodeRoadElement`/`EdgeRoadElement`,
centerline/clothoid, lokalizovanih name adaptera i osnovnih road-property
adaptera za 3G Plus. AdvancedRouting/ADAS recordi su stabilan lossless ulaz za
dalji semantic decoder, ali još nisu gotove Orion manevar/ADAS kolone.
Rutabilna `.ATLAS` baza čeka njihovu semantiku, preostale Basic pod-enume i
stavku 7.

Operativni handoff sa ulazima, hash-evima, firmware adresama, komandama,
zamkama i tačnom granicom nastavka je u `docs/CLAUDE_HANDOFF.md`.

### Container/blok sloj — prvi profil, 2026-09-03

Stavka 3 (catalog/container) je do sada bila jedina neprofilisana. Novi
read-only alat `tools/orion_block_header_profile.py` prolazi ceo originalni
PSD3 i čuva `blocks.jsonl` za svaki blok. Rezultat u
`out/orion_block_header_profile/`:

- 43.402 bloka, `covered_bytes = file_size`, `file_coverage = 1.0`;
- samo dva imena bloka: `HEADER` (1) i `CONTAINER` (43.401);
- verziona reč `+0x14` je uniformna: `0x00000105`, odnosno `0x00010105` za
  `HEADER`;
- chunk kind/count je `3/3` na 42.899 blokova, `1/8` na 502 i `5/79` na
  `HEADER`; iskorišćen je tačno jedan `(csize,usize)` slot na 42.882 bloka i
  dva na 17;
- reč `+0x18` se čita kao dva `u16`: prvi je mala vrednost 20..28, drugi je
  186-vrednosni ključ koji raste kroz fajl pa se resetuje — kandidat za
  prostorni/quadtree ključ, još neimenovan;
- reč `+0x1c` je `0xf0000000` na 35.320 blokova, a ne-sentinel na 8.082, što
  se poklapa sa 8.081 graph/property chunkom iz
  `out/orion_property_corpus_profile/`.

Ranija beleška o "konstantnoj" reči na `+0x1c` i o `+0x38` bajtovima je
ispravljena: `+0x1c` nije konstanta, a `+0x38` pada unutar treće
`(csize,usize)` stavke pa se ne sme čitati kao zaseban tail.

Ništa od ovoga još nije semantički imenovano niti upisano u writer.

### Stavka 3 zapoceta — container gramatika zatvorena, indeks lociran, 2026-09-03

Puna specifikacija je u `docs/ATLAS_CONTAINER.md`. Sazeto:

- `HEADER` blok je dokazan preko sve cetiri baze izdanja 6.36.0 i njihovih
  10 delova. Polja `total_size`/`part_size`/`preceding_size` opisuju lanac
  medijskih delova i sve tri relacije prolaze bez odstupanja (delta 0).
  `tools/orion_atlas_header_decode.py`, izlaz
  `out/orion_atlas_header_decode/`.
- `CONTAINER` gramatika je zatvorena: `tools/orion_block_grammar_verify.py`
  objasnjava svaki bajt svakog bloka. PSD3 daje 43.402/43.402. Sest od osam
  ATLAS fajlova prolazi bez ijednog neuspeha; u preostala dva neobjasnjeni
  blokovi su tacno `REVISION`/`INDEX`.
- Ispravljene su dve ranije pretpostavke: terminator je poslednjih 16 B
  bloka, a ne odmah iza payload-a; i bajt na `+0x20` je codec, pa codec-1
  blokovi nemaju chunk tabelu nego payload odmah na `+0x21`.
- Codec ima tri vrednosti: 1 nekompresovano, 2 zlib, 3 LZMA1 raw. Cela PSD
  baza koristi 3, CTY/TER koriste 1, CTYS3TC koristi 2.
- Velicinski invariant za codec 2/3 je
  `block_size == align16(data_offset + zbir(csize) + 16)`.
- **Indeksni sloj je lociran.** Postoji samo u nultom delu baze, odmah iza
  `HEADER`-a: `REVISION` (4096 B) pa niz `INDEX` blokova (PSD 126, CTY 255,
  TER 428; pretezno 41.008 B). Zato ga raniji rad nije mogao naci — sav
  raniji rad je bio nad PSD3, koji je deo 2.
  `tools/orion_index_block_profile.py`, izlaz
  `out/orion_index_block_profile/`.

Otvoreno u stavci 3: unutrasnji zapis `INDEX` bloka nije dekodiran. Period
8 B se vidi na pocetku bloka ali ne vazi kroz ceo blok, pa ne pretpostavljati
fiksni zapis. Polja A/B u `CONTAINER` zaglavlju i sadrzaj `REVISION` bloka
takodje ostaju neimenovani.

### Stavka 3 — indeks dekodiran, round-trip zatvoren, kljuc dokazan, 2026-09-03

Puna specifikacija u `docs/ATLAS_CONTAINER.md`. Zatvoreno:

- **Indeksno stablo**: REVISION → koren INDEX (128 stavki) → 125 listova
  (2048 stavki) → blokovi. Jedno pravilo na svim nivoima: separator =
  kopija zaglavlja `(A, K)` prvog bloka sledeceg deteta. Puna provera nad
  PSD (3 dela, 254.958 blokova): 254.703/254.703 stavki tacne, koren
  124/124, 0 neuspeha. Offseti su u adresnom prostoru cele baze.
- **Round-trip bloka**: `tools/orion_block_writer.py` daje 43.401/43.401
  bajt-identicnu strukturu i 43.401/43.401 semanticki codec round-trip nad
  PSD3, 0 neuspeha.
- **Ispravka**: 835 "korumpiranih" LZMA blokova iz ranije dokumentacije
  nisu korumpirani; rečnik je 1 MiB, ne 64 KiB. Svi alati koji raspakuju
  moraju koristiti `dict_size = 1 << 20`.
- **Kljuc bloka**: `K = C << 8 | B_hi` je Z-preplet pocetka celije jednog
  globalnog binarnog stabla sa naizmenicnim osama; `A` je nivo,
  `lon = 2^((A+17)//2)`, `lat = 2^((A+16)//2)`, `K_base = 0x1018000000`.
  Egzaktno na 7.015/7.015 graph blokova PSD3.
- Orkestrator `tools/run_container_pipeline.py` (zavisnosti, paralelizam,
  gate izrazi, `on_fail` trijaza) i manifest `tools/orion_container_pipeline.json`.
- Testovi: `tests/test_orion_container.py` (8 testova).

Otvoreno pre writera celog fajla: blokovi bez kljuca (sta su, kako se
referenciraju), politika deljenja celije (prag za `A`), HEADER `+0x3c` i
`build_id`, potvrda `K_base` na PSD delovima 0 i 1.

### Container writer dokazan round-trip-om celog paketa — 2026-09-03

`tools/orion_atlas_assemble.py` ponovo sastavlja kompletan PSD (3 dela,
5.037.063.424 B) iz sopstvenih blokova: 0 odstupanja u 130 sintetizovanih
oblasti, 254.828/254.828 blokova na istim pozicijama. Formula kljuca bloka
potvrdjena na sva tri dela (deo 0: 103.188, deo 1: potvrdjeno, deo 2: 7.015).
Testovi: 12 u `tests/test_orion_container.py`, puni suite 140+ OK.

Time je stavka 3 (container/indeks) zatvorena za PSD 5.1 format. Preostalo
za rutabilnu bazu iz MIB izvora: particionisanje MIB grafa u celije stabla
(politika 64 KiB, pod A=18), generisanje chunka po celiji postojecim
`orion_merged_graph_writer` slojem, kompresija i sklapanje; zatim pitanje
VidTable blokova i `.conf` sa MD5.

Orkestrator `tools/run_container_pipeline.py` sa manifestom
`tools/orion_container_pipeline.json` prolazi 9/9 faza (header, gramatika,
indeks, koren, block round-trip, prostorni kljuc, formula, mreza, asembler
round-trip); `lzma-failure-probe` je trijazna faza koja se pokrece samo ako
block round-trip padne. Puni upis PSD paketa daje MD5 identican `.conf`-u.

### MIB → ATLAS lanac i lanac prihvatanja paketa — 2026-09-03

Lanac `orion_cell_partition` → `orion_cell_chunk_writer` →
`orion_atlas_assemble --blocks` → `orion_conf_write` radi end-to-end na
uzorku i prolazi sve nase citace; puna izgradnja 3.429 celija Serbia
korpusa je u toku. `.conf` self-test nad originalom reprodukuje `size`,
`MD5` i dva od tri quick-check MD5.

**Kriticno za instalaciju:** `.pkg` (potpisan `.pkg.sig`) nosi
`fdefcrc` = `checkcrc` svakog `.conf`-a (21/21 poklapanje), a `.conf` nosi
MD5 ATLAS-a. Novi sadrzaj → novi MD5 → novi `.conf` CRC → `.pkg` koji ne
mozemo potpisati. Firmware stringovi `fdefcrc`/`pkg.sig`/`MetafileChecksum`
postoje u `usr/bin/vdev-logvolmgr` i `usr/apps/MMI3GNavigation`; ko i kada
verifikuje potpis tek treba dokazati u Ghidri. Do tada ne planirati device
test.

### Puni Serbia ATLAS generisan i validiran nasim citacima — 2026-09-03

`out/orion_atlas_build_full/pkg/SRB.5_1.0.ATLAS` (32.303.664 B): 3.915
graph blokova iz 717.730 cvorova / 838.433 edge-ova (161 edge-a bez
geometrije izostavljeno), 1 deo, 2 INDEX lista. Provere:

- gramatika 3.920/3.920, coverage 1.0;
- indeks 0 neuspeha (3.913 stavki tacne, lanac listova neprekidan);
- block round-trip 3.915/3.915 struktura i codec;
- kljuc bloka egzaktan 3.915/3.915, bbox staje u celiju 3.915/3.915,
  pomaci 0x44000/0x2000 nezavisno izvedeni iz naseg fajla;
- max dekodirani chunk 65.440 B (≤ 64 KiB, kao original).

Particija ide po cvorovima (edge prati pocetni cvor); 50.519 od 1.676.866
endpoint-a je spoljno (3,0%). `PSD.conf` je napisan sa `size`/`MD5`, bez
`check=`/`checkcrc=`.

Nije ukljuceno: VidTable blokovi, Property klase osim Adas/Urban/AudiUrban,
AdvancedRouting/ADAS. Nije testirano na uredjaju.

### Stavka 3 ZAVRŠENA — container/index writer, 2026-09-03

Puna specifikacija u `docs/ATLAS_CONTAINER.md`. Sažeto:

- HEADER blok dokazan preko 4 baze / 10 delova (part_size/total_size/
  preceding_size, delta 0).
- CONTAINER gramatika: svaki bajt objašnjen, PSD3 43.402/43.402, 6/8 fajlova
  bez ijednog neuspeha.
- INDEX direktorijum dekodiran: separator = kopija zaglavlja sledećeg bloka
  (A, K); `offset[i]+size[i]==offset[i+1]`. Nad originalnom PSD bazom 0
  neuspeha na 254.703 stavke.
- `orion_atlas_assemble.py` sastavlja kompletan fajl (HEADER/REVISION/INDEX/
  blokovi) + `.conf` sa tačnim size/MD5.
- Generisani `SRB.5_1.0.ATLAS` (32,3 MB) prolazi grammar/index/roundtrip/
  formula/spatial — sve zeleno, 0 neslaganja.

Ceo lanac MIB → ATLAS je time strukturno kompletan i samodosledan. Model
zaštite (potpis/FSC) je dokumentovan u `docs/FW_PROTECTION_MODEL.md`;
prihvatanje na uređaju zahteva izdavačev potpis paketa.

### Ostali pkgdb slojevi — format rešen (2026-09-03)

„Stavka 1" (ATLAS nije cela baza): rešen format svih slojeva. Detalji u
`docs/PKGDB_LAYERS.md`. Sažeto:

- **CTY/CTYS3TC** (3D gradovi): Orion .ATLAS, legacy schema; dekodiran pun 3D
  scene format (AbsolutePoint/VertexArray/Material/Texture/Normal/Color/
  Primitive/Geometry/ImagePointer).
- **TER** (teren): Orion .ATLAS, composite `SoarTerrain` (Heights/Errors/Radia),
  SOAR LOD mesh.
- **LIT/LIT3GP** (tekst): FLDB → `.LIT` (legacy zlib engine v3.8.7).
- **TMC** (saobraćaj): FLDB → `.tlt` RDS-TMC location tabele.
- **XAC** (POI/imena): FLDB → 439 fajlova; vector/name most već detaljno RE-ovan.

Dva porodična formata: Orion `.ATLAS` (PSD/CTY/TER — container potpuno rešen) i
FLDB `.db` (LIT/TMC/XAC — wrapper rešen). Alat `tools/orion_layer_survey.py`.
Container/direktorijum/šema dekodirani i sadržaj čitljiv za sve; puni per-sloj
semantički writer je zaseban obiman posao. Prihvatanje na uređaju zahteva
izdavačev potpis paketa.
