# ATLAS container — dokazana specifikacija bloka

Poslednje azuriranje: 2026-09-03. Ovo je stavka 3 iz `IMPLEMENTATION_STATUS.md`
(catalog/container), koja do sada nije bila zapoceta. Sve dole navedeno je
izvedeno merenjem nad originalnim fajlovima i provereno kao tvrdi invariant;
nista nije preneto iz starijeg MMI3G rada bez ponovne provere.

Ulazi su read-only. Nijedan ATLAS fajl nije menjan.

## Alati

- `tools/orion_atlas_header_decode.py` — dekodira i proverava `HEADER` blok
  svih ATLAS baza jednog pkgdb izdanja;
- `tools/orion_block_header_profile.py` — profil zaglavlja svih blokova;
- `tools/orion_container_header_decode.py` — bajt-po-bajt profil CONTAINER
  zaglavlja sa raspodelama;
- `tools/orion_block_grammar_verify.py` — tvrda provera da je svaki bajt
  svakog bloka objasnjen.

Izlazi: `out/orion_atlas_header_decode/`, `out/orion_block_header_profile/`,
`out/orion_container_header_decode/`, `out/orion_block_grammar_verify*/`.

## Fajl kao lanac blokova

ATLAS je ravan niz blokova. Sledeci blok pocinje na `offset + block_size`.
Lanac pokriva fajl tacno na svih osam ATLAS fajlova izdanja: `file_coverage`
je 1.0 svuda.

Postoje cetiri imena bloka, a raspored zavisi od toga koji je deo baze:

    deo 0:  HEADER, REVISION, INDEX * N, pa CONTAINER do kraja
    deo 1+: HEADER, pa CONTAINER do kraja

Zato indeksni sloj nije bio vidljiv u dosadasnjem radu: sav raniji rad je
bio nad PSD3, a to je deo 2 i nema nijedan `INDEX` blok.

Svaki blok pocinje jednako:

    +0x00  u8 duzina imena, pa ime u ASCII
    ...    popuna do 0x10 jednim bajtom (0xcc za HEADER, 0xcb za CONTAINER)
    +0x10  u32 velicina bloka, uvek visekratnik 16
    +0x14  u8[4] format verzija {major, minor, rev, 0}

Poslednjih 16 B svakog bloka je konstantni terminator
`0123456789abcdeffedcba9876543210`. Nije na kraju payload-a nego na kraju
bloka; izmedju stoji popuna debug bajtovima `0xca`/`0xcb`/`0xcc` duzine
0..15 B, koja ne nosi podatak.

## HEADER blok

Fiksno 4096 B. Verzija je `5.1.1` za PSD, `4.2.1` za CTY i TER, `4.4.1` za
CTYS3TC — isti brojevi koje nosi ime fajla (`APN...5_1.2.ATLAS`).

    +0x18  u16   konstanta 0x016c
    +0x1a  u8    ukupan broj delova baze
    +0x1b  u8    indeks ovog dela
    +0x1c  u32   identifikator baze (0 za PSD)
    +0x20  u8 duzina + "Orion"   (engine), polje 8 B
    +0x28  u32   100
    +0x2c  u32   0
    +0x30  u8 duzina + "Atlas"   (kontejner), polje 12 B
    +0x3c  u16 + u16             jos neimenovan par
    +0x40  u64   build identifikator, isti za sve delove jedne baze
    +0x48  u64   ukupna velicina svih delova baze
    +0x50  u64   velicina ovog dela = velicina fajla
    +0x58  u64   zbir velicina svih prethodnih delova
    +0x60  popuna 0xcc do 4096

Jedna logicka baza je podeljena na 2-3 fajla, a polja `+0x48/+0x50/+0x58`
opisuju taj lanac. Provera nad sve cetiri baze izdanja 6.36.0 prolazi bez
odstupanja:

| Baza | Verzija | Delova | Ukupno B | Delta |
|---|---|---:|---:|---:|
| `3PN221EU22083H1665a.4_2` (CTY) | 4.2.1 | 3 | 5.194.601.248 | 0 |
| `3PN221EU22083P1666a.4_4` (CTYS3TC) | 4.4.1 | 2 | 2.658.930.736 | 0 |
| `72_Europe.4_2` (TER) | 4.2.1 | 2 | 2.214.189.520 | 0 |
| `APN221EU22093P1664a.5_1` (PSD) | 5.1.1 | 3 | 5.037.063.424 | 0 |

Za svaki deo vazi `part_size == velicina fajla`, `preceding_size` je tacan
tekuci zbir prethodnih delova, a `total_size` je zbir svih. Indeksi delova su
kompletan niz `0..part_count-1`.

To znaci da writer koji pravi novu bazu mora popuniti ova polja dosledno u
svim delovima; ona su jedina veza izmedju fajlova jedne baze.

## CONTAINER blok

Verzija je `5.1.0` na svih 43.401 CONTAINER blokova PSD3.

    +0x18  u16 A     0..44745, 35.323 razlicitih vrednosti
    +0x1a  u16 B     donji bajt uvek 0; gornji bajt ima 186 vrednosti
    +0x1c  u32 C     0xf0000000 na 35.320 blokova, stvarna vrednost na 8.082
    +0x20  u8  codec

Codec ima tri posmatrane vrednosti, a koja se koristi zavisi od baze:

- **codec 1 — nekompresovano.** Payload pocinje odmah na `+0x21`. U PSD3 je
  takvih 502 i svi nose chunk ime `VidTable`. CTY i TER koriste ovaj codec
  za skoro sve blokove.
- **codec 2 — zlib.** Koriste ga CTYS3TC i CTYS3TC2. Framing je isti kao
  kod codec 3.
- **codec 3 — LZMA1 raw** (`lc=3, lp=0, pb=2, dict=1 MiB`). Na `+0x21` stoji
  `u8` broj stavki, pa toliko parova `(u32 csize, u32 usize)`, pa payload.
  Koristi ga cela PSD baza. U PSD3 je broj stavki uvek 3, ali je iskoriscena
  jedna stavka na 42.882 bloka i dve na 17.

Dekodirani chunk u oba slucaja pocinje kao `u8 duzina + ime`; posmatrana
imena su `Map` i `VidTable`.

Za codec 3 vazi tacan velicinski invariant:

    block_size == align16(data_offset + zbir(csize) + 16)

gde je `data_offset = 0x22 + count * 8`.

## Rezultat provere

`orion_block_grammar_verify.py` objasnjava svaki bajt svakog `CONTAINER` i
`HEADER` bloka: ime, popuna imena, zaglavlje, chunk tabela, payload, popuna,
terminator.

| Fajl | Blokova | Coverage | Objasnjeno | Neobjasnjeno |
|---|---:|---:|---:|---:|
| PSD3 | 43.402 | 1.0 | 43.402 | 0 |
| PSD2 | 106.865 | 1.0 | 106.865 | 0 |
| CTY2 | 280.995 | 1.0 | 280.995 | 0 |
| CTY3 | 25.529 | 1.0 | 25.529 | 0 |
| CTYS3TC2 | 35.732 | 1.0 | 35.732 | 0 |
| TER2 | 140.847 | 1.0 | 140.847 | 0 |
| PSD | 104.691 | 1.0 | 104.564 | 127 |
| CTY | 213.299 | 1.0 | 213.043 | 256 |
| CTYS3TC | 484.090 | 1.0 | 483.834 | 256 |
| TER | 733.399 | 1.0 | 732.970 | 429 |

Svih sest fajlova koji nisu deo 0 prolaze bez ijednog neuspeha. Neobjasnjeni
blokovi u delovima 0 su tacno `REVISION` i `INDEX` blokovi, koji imaju
drugaciji sadrzaj iza `+0x18` i nisu chunk kontejneri.

## Indeksna zona u nultom delu

Odmah iza `HEADER`-a stoji `REVISION` (4096 B, verzija 5.1.1), pa niz
`INDEX` blokova, pa tek onda podaci:

| Baza | INDEX blokova | Velicine |
|---|---:|---|
| PSD | 126 | 124 x 41.008 B, po jedan 2.608 i 20.528 |
| CTY | 255 | pretezno 41.008 B |
| TER | 428 | pretezno 41.008 B |

Zona zauzima oko 0,1% fajla i zavrsava se pre prvog `CONTAINER` bloka.
`INDEX` zaglavlje ima na `+0x18` bajtove oblika `02 0b 01 <n>`, gde `<n>`
uzima vrednosti oko 0x12..0x1c.

Unutrasnji zapis `INDEX` bloka **jos nije dekodiran**. Na pocetku bloka
jasno se vidi obrazac perioda 8 B (`u32` mala vrednost 0x17..0x1c, pa `u32`
koji raste, npr. `0x100d9ecc`, `0x100d9ed8`, `0x100d9edc`), ali taj period
ne vazi kroz ceo blok: ni faza `0x20` ni faza `0x23` ne daju monotoni kljuc
preko svih zapisa. Dakle blok nije prost niz fiksne velicine — verovatno ima
vise sekcija ili promenljive zapise. Ne pretpostavljati fiksni zapis.

Vazna veza: rastuci `u32` u `INDEX` zapisima (`0x100d9ecc`) je istog reda
velicine kao polje C u `CONTAINER` zaglavlju PSD3 (`0x101b414f..0x101f25d0`).
To je jak nagovestaj da je C kljuc koji indeks adresira, ali dok se zapis ne
dekodira to ostaje nagovestaj, ne dokaz.

## Indeksno stablo (dokazano)

Sve tri nivoa koriste isto pravilo: **separator = kopija zaglavlja prvog
bloka sledeceg deteta**.

    REVISION (4096 B)
      +0x18 u16 = 1
      +0x1c u32 = velicina korenskog INDEX bloka
      +0x20 u32 = offset korenskog INDEX bloka
    INDEX koren (nivo 1, 128 stavki)
      stavke = (offset, velicina) svakog INDEX lista, redom;
      separator i = (A, K) prvog bloka lista i+1;
      neiskoriscene stavke ponavljaju poslednju.
    INDEX list (nivo 2, 2048 stavki; poslednji 1024)
      stavke = (offset, velicina) uzastopnih blokova cele baze;
      separator i = (A, K) bloka i+1;
      posle poslednjeg bloka baze stavke ponavljaju poslednju.

Raspored INDEX bloka:

    +0x18  u8 nivo, u8 log2(stavki), u8 1
    +0x1b  u24 A | u40 K sopstvenog prvog bloka (separator kojim roditelj
           vodi do ovog cvora); prvi list i koren nose nule
    +0x23  (stavki-1) separatora: u24 A | u40 K   (little-endian)
    ...    stavki offseta u64, pa stavki velicina u32, popuna 5 B, terminator

Offseti su u adresnom prostoru cele baze (delovi nadovezani po
`preceding_size`); na granici dela preskace se 4096 B `HEADER` narednog
dela.  Puna provera nad PSD (3 dela, 254.958 blokova): 254.703/254.703
stavki ima tacnu velicinu, tacan `K` i tacan `A` sledeceg bloka; lanac
listova 124/124; koren 124/124; 0 neuspeha.
`tools/orion_index_decode.py`, `tools/orion_index_root_decode.py`.

Stariji format 4.x (CTY, TER, CTYS3TC) ima isti raspored i isto pravilo
za `K` (100%), ali `A` i redosled kljuceva se razlikuju; nije analizirano
dalje jer PSD 5.1 je cilj.

## Asembler celog fajla (dokazano)

`tools/orion_atlas_assemble.py` iz uredjenog niza blokova pravi sve delove
baze: HEADER po delu, REVISION, koren i listove indeksa, blokove; racuna
globalne offsete i velicine delova. Round-trip nad originalnim PSD
(3 dela, 254.828 blokova): svih 130 sintetizovanih oblasti (3 HEADER,
REVISION, koren, 125 listova) je bajt-identicno originalu, svaki blok je na
identicnoj poziciji, sve tri velicine delova se poklapaju — **0 odstupanja**.
Velicina INDEX bloka je `align16(0x23 + (n-1)*8 + n*8 + n*4 + 16)`
(41.008 / 20.528 / 2.608 za n = 2048 / 1024 / 128).

Sa `--write` asembler upisuje kompletne fajlove; MD5 sva tri upisana dela
je identican `MD5=` vrednostima iz `PSD.conf`, `PSD2.conf` i `PSD3.conf`
(`c88ef8df…`, `76238a06…`, `1c624a21…`). Time je zatvoren i integritet:
`.conf` za novi paket dobija `size=` i `MD5=` iz istog koda.

## Kljuc bloka (dokazano)

`K = (u32 na +0x1c) << 8 | (visoki bajt u16 na +0x1a)`, `A = u16 na +0x18`.

Graph blokovi su listovi jednog globalnog **binarnog** stabla nad
pohranjenim koordinatama (`degree x 1e7`, signed, sidreno na nuli) koje na
svakom nivou deli jednu osu, naizmenicno:

    p = (A + 17) // 2        lon stranica celije = 2^p
    q = (A + 16) // 2        lat stranica celije = 2^q
    x0 = lon0 >> p << p      y0 = lat0 >> q << q
    X  = (x0 >> 17) + 0x44000
    Y  = (y0 >> 17) + 0x2000
    K  = interleave20(X, Y)  -- Z-preplet, bit Y u visem bitu para

Pomaci `0x44000`/`0x2000` su pomaci u prostoru kljuca (drze X/Y pozitivnim
za zapadnu hemisferu), ne geografski. Provereno egzaktno na PSD delu 0
(103.188/103.188, ukljucujuci negativne longitude) i delu 2 (7.015/7.015);
pomaci su izvedeni nezavisno iz podataka i konstantni su na svim blokovima.
`A` ide od 18 (najfinije, 2^17 x 2^17) do 28. `tools/orion_tile_formula_verify.py`,
`block_key(A, lon0, lat0)` je referentna implementacija.

**Blokovi bez kljuca** (`C = 0xf0000000`, 35.320 u PSD3) su bez izuzetka
`VidTable` chunkovi (34.818 codec 3 + 502 codec 1). Kod njih je `A`
identifikator: strogo rastuci kroz fajl, 35.320 razlicitih vrednosti u
opsegu 0..44745 (rupe su verovatno u drugim delovima). Posto separator u
indeksu nosi `(A, K)`, VidTable se pronalazi po `A` uz sentinel `K`.
`tools/orion_nonkey_block_profile.py`.

**Politika deljenja** (posmatrano, ne firmware-dokazano): dekodirani graph
chunk je ≤ 65.536 B na svih 7.015 blokova PSD3 (max 65.041). U delu 0 je
888 od 103.188 vecih od 64 KiB, od toga 879 na najfinijem nivou `A = 18` —
dakle celija se deli dok chunk ne stane u 64 KiB, a `A = 18` je pod kojim
se vise ne deli. Preostalih 9 izuzetaka (A 24..26) nisu objasnjeni.

## Kompresija (ispravka)

Ranija dokumentacija je 835 LZMA neuspeha u PSD3 vodila kao
`Corrupt input data`.  Nisu korumpirani: raspakuju se sa
`dict_size = 1 MiB`.  Sa tim parametrom `tools/orion_block_writer.py`
daje 43.401/43.401 bajt-identicnu strukturu i 43.401/43.401 semanticki
codec round-trip, 0 neuspeha.  Nas LZMA izlaz je bajt-identican
originalu samo u 1.652 slucaja — to nije uslov, jer uredjaj raspakuje.

## `.conf` integritet

`tools/orion_conf_write.py selftest` nad originalnim `PSD3.conf`: `size`,
`MD5` i prva dva quick-check MD5 (`md5(prvih 100 KiB)`,
`md5(100 KiB od size//2)`) se reprodukuju tacno. Treci quick-check MD5 i
`checkcrc` nisu reprodukovani; po Harman dokumentaciji MD5 je primaran, a
CRC32 "for testing only". `write` rezim izostavlja `check=`/`checkcrc=`
osim ako se prosledi vrednost — to je otvorena stavka do device testa.

## MIB → ATLAS lanac (vertikalni presek)

    orion_cell_partition.py   MIB graf -> celije stabla (A, x0, y0, K, id-jevi)
    orion_cell_chunk_writer.py  celija -> dekodirani chunk (postojeci merged
                                writer) -> LZMA -> CONTAINER blok sa kljucem
    orion_atlas_assemble.py --blocks  blokovi -> HEADER/REVISION/INDEX/delovi
    orion_conf_write.py       .conf sa size/MD5

Na uzorku od 100 redova lanac daje ATLAS koji prolazi sve nase citace:
gramatika 7/7 (3 u index zoni), indeks 0 neuspeha, HEADER 0 neuspeha,
block round-trip 3/3. Puni Serbia korpus: 3.429 celija (A 18..33, do 697
edge-ova po celiji), 49.033 od 1.676.866 endpoint-a spoljno (2,9%; original
ima ~7%).

## Lanac prihvatanja paketa — KRITICNO za instalaciju

    MMI3GP_*.pkg.sig (128 B)  potpis nad .pkg
    MMI3GP_*.pkg              [crcs] fdefcrc=<FILEDEF>,<CRC32> za svaki .conf
    <DB>/<DB>.conf            size=, MD5= (ATLAS), check=, checkcrc=<isti CRC>
    <DB>/<ime>.ATLAS          sadrzaj

`fdefcrc` u `.pkg` je identican `checkcrc` u odgovarajucem `.conf`-u (sve
baze), a `.pkg` je potpisan. Ako uredjaj verifikuje potpis i CRC lanca,
novi ATLAS (drugi MD5) zahteva novi `.conf` → novi CRC → novi `.pkg` → novi
potpis, koji ne mozemo napraviti. Da li se potpis i lanac stvarno
proveravaju, i u kom procesu (SWDL instalacija vs. NavCore runtime), jos
nije dokazano firmware-om. Ovo je najveci otvoreni rizik za krajnji cilj i
mora se razresiti pre bilo kakvog device testa. `metainfo2.txt` dodatno nosi
`MetafileChecksum`.

## Sta je jos otvoreno

1. Kako graph blokovi referenciraju VidTable blokove (po `A`?), i da li je
   VidTable uopste potreban za rutabilnu bazu.
2. Firmware potvrda politike deljenja (64 KiB, pod `A = 18`) i 9 izuzetaka.
3. Polja `+0x3c/+0x3e` i `build_id` u HEADER-u nisu protumacena.
4. Potvrda formule kljuca na PSD delu 1 (u toku).

## Potpis i FSC — nalazi iz firmware stringova (2026-09-03)

`usr/apps/MMI3GNavigation` sadrzi `CPNavDBChecker` sa bitovima greske:
`FSC_FAILED`, `SIGNATURE_FAILED`, `VERSIONCHECK_FAILED`, `NO_NAV_MEDIUM`,
`REGIONCHECK_FAILED`, `ISDOWNGRADE`, `ISUPGRADE`, `VARIANTCHECK_FAILED`,
`CRCCHECKFAILED`, `PACKET_CHAIN_INCOMPLETE`. Potpis se cita iz
`%s/pkgdb/%s.pkg` + `.pkg.sig`; verifikacija je RSA + SHA-1 sa javnim
kljucem (`EscSha1_*`, "Reading public key failed", u `MMI3GApplication` i
`MMI3GMisc`).

Vazno: u firmware-u postoje i konfiguracioni prekidaci
`skipCheckSignatureAndVariant`, `skipCheckRegion`,
`skipCheckConsistencyImages`. Njihovo postojanje znaci da provera potpisa
ima predvidjen bypass put i da re-potpisivanje mozda nije nuzno. Sta ih
postavlja i da li su dostupni bez dirania uredjaja **nije dokazano** i mora
se razresiti u Ghidri pre bilo kakvog device testa.

`vdev-logvolmgr` je taj koji cita `fdefcrc`/`checkcrc`, racuna MD5 i loguje
"MD5 is matching file definition specification" i "Md5 is preferred, while
CRC32 is for testing only". `.pkg` nosi `fdefcrc` = `checkcrc` svakog
`.conf`-a; poklapanje je 21/21.

## Container writer — završeno (2026-09-03)

Stavka 3 (catalog/container) je zatvorena. Alati:

- `tools/orion_index_decode.py` — dekoder INDEX direktorijuma (dole);
- `tools/orion_cell_chunk_writer.py` — pravi CONTAINER blokove iz MIB grafa,
  jedan po prostornoj ćeliji, sa ključem po dokazanoj mreži;
- `tools/orion_atlas_assemble.py` — sastavlja kompletan fajl: HEADER,
  REVISION, INDEX stablo (koren + listovi), blokovi; piše i `.conf` sa
  tačnim `size` i `MD5`.

### INDEX direktorijum — dekodiran

INDEX blok je direktorijum bloka (ne B-stablo sa decom u drugim blokovima):

    +0x18  u8 nivo (1 = koren, 2 = list)
    +0x19  u8 log2(broj stavki)
    +0x23  (stavki-1) separatora po 8 B:  u24 A | u40 K
    ...    stavki offseta (u64), pa stavki velicina (u32)

Separator `i` je kopija zaglavlja bloka `i+1`: `A` = u16 na +0x18 tog bloka,
`K = (u32 na +0x1c) << 8 | (u16 na +0x1a >> 8)`. Kljucevi su strogo rastuci;
`offset[i] + size[i] == offset[i+1]` (izuzeci: granica dela preskace HEADER
4096 B, i popuna na kraju baze ponavlja poslednju stavku).

Provera nad originalnom PSD bazom (3 dela, 254.828 CONTAINER blokova):
**0 neuspeha** — svaka stavka pokazuje na stvarni blok tacne velicine, i
`kljuc == zaglavlje sledeceg bloka` za svih 254.703 proverenih stavki.

### Roundtrip nad originalom — bajt-identično

Definitivni dokaz da writer ume da napravi identičan fajl:
`orion_atlas_assemble.py` je uzeo originalnu PSD bazu (3 dela, 5,04 GB,
254.828 blokova), ponovo sintetizovao HEADER/REVISION/INDEX (130 oblasti) i
uporedio bajt-po-bajt, a raspored svih blokova offset-po-offset:

- `block_layout_matches = 254.828`
- `synthesized_regions = 130`, `mismatch_count = 0`
- `part_sizes_match = [true, true, true]`, `exact = true`

Dakle rekonstrukcija je identična originalu — writer je potpun i tačan.

### Generisani ATLAS — prolazi sve verifikatore

`SRB.5_1.0.ATLAS` (32,3 MB, 3915 graph blokova) generisan iz MIB Serbia grafa:

| Verifikator | Rezultat |
|---|---|
| grammar (svaki bajt objasnjen) | 3920/3920, coverage 1.0 |
| index (stablo, kljucevi, offseti) | 0 neuspeha |
| roundtrip (struktura + codec) | 3915/3915 bajt-identicno |
| formula (K iz koordinata) | `exact` |
| spatial (K strogo rastuci u fajlu) | 3915 razlicitih, bbox lon 0.0511 ≈ 2×lat 0.0261 |

Prateci `PSD.conf` ima tacan `size` i `MD5` generisanog fajla.

To je strukturno kompletna, samodosledna ATLAS baza. Prihvatanje na uredjaju
zahteva izdavacev potpis paketa (vidi `docs/FW_PROTECTION_MODEL.md`).
