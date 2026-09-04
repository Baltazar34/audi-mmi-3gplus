# MMI 3G+ `.ATLAS` — reverse engineering

Radna dokumentacija. Održava se u hodu; namenjena je i za offload konteksta u novu sesiju.

**Poslednja izmena:** 2026-08-31

---

## 1. Cilj i granice

Razumeti binarni format `.ATLAS` baze navigacije za Audi A6 C7 sa MMI 3G Plus, da bi se **postojeća baza mogla menjati** (imena ulica, POI, geometrija) uz zadržavanje originalnog identiteta.

**Scope koji je postavljen i drži se:**

- Jedinica u autu se **ne dira** — bez flashovanja, bez telneta, bez patchovanja. Sve se radi nad fajlovima na Macu.
- Firmware se **čita**, ne menja. Binarni fajl je jedina postojeća dokumentacija formata.
- Zadržava se originalni `PartNumber` — FSC aktivacija je vezana za njega.

**Stepenovanje ciljeva:**

| | Cilj | Ocena |
|---|---|---|
| A | Izmena postojeće baze, originalni PartNumber | dostižno, ovo je cilj |
| B | Regeneracija jednog tajla iz OSM-a | teško, ali nije fantazija |
| C | Cela Evropa iz OSM-a | van dohvata, nije pitanje truda |

Reverse engineering formata radi interoperabilnosti je u EU dozvoljen (Direktiva 2009/24/EZ, čl. 6). Granica je redistribucija HERE podataka, ne analiza.

---

## 2. Konfiguracija

| Stavka | Vrednost |
|---|---|
| Jedinica | MMI 3G Plus, grana **HN+R** (A6/A7/A8/Q3) |
| Firmware | `HN+R_EU_AU_K0942_4`, Audi part `8R0906961FB` — poslednja zvanična EU verzija |
| Baza u autu | `8R0060884JN`, ECE **6.34.1** |
| Analizirano izdanje | `8R0060884KL`, ECE **6.36.0** (fajl nosi ime `8R0051884KL`) |
| Uređaj u firmveru | `MU9411` — potvrđeno preko `variant3 = "9411"` u `metainfo2.txt` |
| Vendor | Becker Automotive |

> **Zamka sa imenovanjem:** arhiv se zove `8R0051884KL`, a `DBInfo.txt` unutra nosi `PartNumber="8R0060884KL"`. Nije greška i nije pogrešan paket — uvek proveravati `DBInfo.txt`, ne ime fajla.

---

## 3. Putanje

```
~/mmi3g-atlas/                      radni folder
  atlas_recon.py                    recon .ATLAS (head/ent/str/coord/period/diff)
  atlas_blocks.py                   parser blok-strukture (scan/block/decode)
  ifs_tool.py                       QNX IFS + sopstveni LZO1X (info/unpack/ls/extract)
  DOCS.md                           ovaj fajl
  MU9411/                           raspakovan firmware paket
  ifs-root-61.raw                   dekompresovan imagefs, 99,4 MB
  extracted/                        345 fajlova iz imagefs-a
  ghidra_proj/                      Ghidra projekat (NavCoreProj)
  ghidra_scripts/*.java             probe skripte
  ghidra_probe.txt, ghidra_probe2.txt   izlazi

<firmware-download-dir>/
  HN+R_EU_AU_K0942_4_[8R0906961FB].zip      firmware, 996 MB

<map-download-dir>/
  8R0051884KL_6.36.0_2023.7z                mape, 23 GiB, solid LZMA2
  8R0051884KL_6.36.0_2023/                  raspakovano
```

Ključni binarni fajl: `extracted/mnt/ifs-root/usr/apps/NavCore` (7 MB, ELF 32-bit LSB, Renesas SH).

---

## 4. Alati

Svi su čist Python 3 stdlib, bez ijedne spoljne zavisnosti.

### `ifs_tool.py` — QNX IFS

Sadrži **sopstveni LZO1X dekompresor** u čistom Pythonu, pa ništa ne treba skidati.

```bash
python3 ifs_tool.py info    MU9411/ifs-root/61/default/ifs-root.ifs
python3 ifs_tool.py unpack  MU9411/ifs-root/61/default/ifs-root.ifs ifs-root-61.raw
python3 ifs_tool.py ls      ifs-root-61.raw
python3 ifs_tool.py extract ifs-root-61.raw extracted
```

Ceo image (41,7 MB → 99,4 MB) za 3,8 s; izlaz se poklapa sa `imagefs_size` iz hedera u bajt.

### `atlas_recon.py` — recon podataka

```bash
python3 atlas_recon.py ent   "$ATLAS" --block 65536
python3 atlas_recon.py head  "$ATLAS" --bytes 256
python3 atlas_recon.py str   "$ATLAS" --min 6 --limit 200
python3 atlas_recon.py coord "$ATLAS" --lat 44.7866 --lon 20.4489
python3 atlas_recon.py diff  6.34.1/PSD.ATLAS 6.36.1/PSD.ATLAS
```

`head` uz heksdump radi i **sektorsku interpretaciju** — svaki `uint32` proverava kao broj sektora (filtrirano na 24 bita) i računa na koji bajt pada.

### `atlas_blocks.py` — blok-struktura

```bash
python3 atlas_blocks.py scan   "$ATLAS" --limit 20
python3 atlas_blocks.py block  "$ATLAS" --index -1
python3 atlas_blocks.py decode "$ATLAS" --index -1
```

`decode` dekodira red vrednosti po šemi bloka i sam ispiše bbox, rezoluciju i proveru kvadrata.

### Ghidra

Instalirana kao **formula, ne cask**: `brew install ghidra` (v12.1.3). **PyGhidra nije uz ovaj build** — skripte pisati u Javi, Ghidra ih kompajlira sama.

```bash
/opt/homebrew/Cellar/ghidra/12.1.3/libexec/support/analyzeHeadless \
  ~/mmi3g-atlas/ghidra_proj NavCoreProj -process NavCore -noanalysis \
  -scriptPath ~/mmi3g-atlas/ghidra_scripts -postScript atlas_probe.java
```

Import: jezik `SuperH4:LE:32:default`, image base `0x08040000`.

---

## 5. Nalazi iz firmvera

### 5.1 QNX IFS

`ifs-root.ifs` je QNX IFS: `machine 42 = EM_SH`, little-endian, **LZO-kompresovan**, 41,7 MB → 104 MB. Format: `[startup_header 256B][startup kod][2B BE dužina][LZO1X blok]…[0x0000]`.

### 5.2 NavCore — adrese

| Šta | Adresa |
|---|---|
| Image base | `0x08040000` |
| String `.ATLAS` | `0x084860d8` |
| Tabela ekstenzija | `0x081b2350` – `0x081b2388`, 15 unosa |
| Skener direktorijuma | `FUN_081b2118` |
| Registracija `.ATLAS` | `FUN_081b3a4c` |
| Atlas singleton | `FUN_081b1710` |
| CDM driver / sektor | `FUN_080a7584`, oko `0x080a80da` |

Izvorni fajlovi po stringovima: `cdm_nav_db_driver.cpp`, `cdm_nav_db_driver_nobss.cpp`.

### 5.3 Klasifikacija paketa

`FUN_081b2118` skenira direktorijum, uzme ekstenziju preko `strrchr(name, '.')` i `strcmp` lancem klasifikuje. Tabela od 15 unosa, redom:

```
.PI2 .PI3 .PI4 .BLB .DON .LI2 .LI3 .LI4 .LI5 .LI6 .LI7 .LI8 .LI9 .GD2 .ATLAS
```

Stari tipovi (`GDB/GD2`, `PIT/PI2-4`, `LIT/LI2-9`) idu u zajedničku registraciju kao par *(klasa, indeks)*.

**`.ATLAS` iskače iz tog lanca** i ide u zaseban podsistem koji se u kodu zove `"Atlas"`. Postoji i `.XAC`, koje nije u tabeli ali postoji kao stvaran paket u izdanju.

### 5.4 Registar `.ATLAS` unosa

`FUN_081b3a4c` radi dedup po **64-bitnom ključu** iz stat-poziva. Ograničenja iz koda:

| Šta | Vrednost |
|---|---|
| Brojač unosa | offset `+0x2d00` |
| Niz unosa | offset `+0x2d08` |
| Veličina unosa | 1152 B (`0x480`) |
| **Maksimum unosa** | **10** |

10 × 1152 = `0x2d00`, niz je fiksno dimenzionisan.

### 5.5 Sektori i plafon od 32 GB

Pristup ide kroz **CDM** sloj koji medij čita kao **ISO9660** (`ISO9660 volume descriptor on sector %1`; `media=IsoImage` u `.conf` to potvrđuje sa druge strane).

Iz koda oko `0x080a80da`:

```c
uVar21 = (uint)DAT_080a80da;          // = 0x7ff
if ((uVar13 & uVar21) != 0)
    assert("0 == (file_offset & (CDM_CD_SECTOR_SIZE()-1))");
...
local_f0 = ... | (int)uVar13 >> 0xb & 0x00ffffff ...
```

- maska `0x7ff` → **sektor = 2048 B**
- `>> 0xb` → bajt-offset u broj sektora
- broj sektora se pakuje u polje široko **24 bita**

**Posledica:** 2²⁴ × 2048 = **tačno 32,0 GiB**. Poznati 32 GB plafon map kartica nije ograničenje SD kartice nego **adresnog polja u formatu**.

> Ograda: širina polja je pročitana iz kombinovanog izraza u dekompajleru (`& 0x00ffffff`, pa `& 0x03ffffff & 0xfcffffff`, što se svodi na istih 24 bita). Logika je jasna, ali to je čitanje izraza, nije komentar iz koda.

---

## 6. Format `.ATLAS`

Interno ime formata je **Orion**, kontejnera **Atlas** — oba stoje kao stringovi u hederu i poklapaju se sa imenima u `NavCore`.

### 6.1 Entropija

Na TER2: prosek 6.96, min 2.18, **506 / 3269 blokova ispod 6.0**. Dakle **nije enkriptovano**; postoje jasno strukturirani regioni (hederi i indeksi), payload je verovatno pakovan po tajlovima.

### 6.2 Heder fajla

Stringovi su **length-prefixed** (bajt dužine pa tekst), popuna je `0xCC`.

```
0x00  06 "HEADER"  + 0xCC padding
0x20  05 "Orion"
0x30  05 "Atlas"
```

Brojna polja, sve u64 little-endian:

| Offset | Značenje | Primer (TER2) |
|---|---|---|
| `0x40` | timestamp, čita se kao `YYYYMMDDhhmmss` | 20071206220312 |
| `0x48` | ukupna veličina kontejnera preko svih delova | 2.214.189.520 |
| `0x50` | **veličina ovog fajla** | 214.194.880 |
| `0x58` | veličina drugog dela | 1.999.994.640 |

Provera: `1.999.994.640 + 214.194.880 = 2.214.189.520` = polje `0x48`.

> **`TER` i `TER2` nisu dva paketa nego dva dela jednog logičkog kontejnera**, i heder to eksplicitno nosi. Isto važi za `PSD/PSD2/PSD3`, `CTY/CTY2/CTY3`, `XAC/XAC2/XAC3`.

### 6.3 Blok-struktura

Fajl je niz blokova. Svaki blok **završava** 16-bajtnim magic-om:

```
01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
```

To su MD5/SHA inicijalne konstante u little-endian. Nije footer fajla nego **terminator bloka**.

Blok počinje length-prefixed imenom uz `0xCC` popunu (`06 HEADER`, `09 CONTAINER`), pa slede zapisi:

```
01 <len> <ime> <tip> <flag>    definicija kolone; flag 0x00 u korenu, 0x01 u listu
02 <tip> <sirina:u32> 01       tip i sirina kolone u bajtovima
<zastavice, po jedna na kolonu>
<spakovan red, sirina = suma sirina>
<16-bajtni magic>
```

**Imena se ne smeju slepo zipovati sa tipovima.** Blok pored kolona nosi i deskriptorske
`01` zapise (npr. `SoarTerrain`, `SoarTerrainDescription`), pa poravnanje ide na dva načina:

| Režim | Gde | Kako |
|---|---|---|
| **1:1** | korenski blok | traži se prozor imena čiji se niz tipova poklapa sa `02` zapisima |
| **1:2** | list mreže | po imenovanoj koloni idu **dva** `02` zapisa: `u32` veličina + `u24` pokazivač; ime nosi drugi iz para |

Primer lista (`decode --index 1`):

```
Heights.size   '%' 4B = 8192          Heights.ptr   '4' 3B = 13107360
Errors.size    '%' 4B = 8192          Errors.ptr    '$' 3B = 13107360
Radia.size     '%' 4B = 0             Radia.ptr     '%' 0B = <prazno>
```

`Heights.size` = 8192 je isti `ContainerSize` kao u korenu — nezavisna potvrda da je
poravnanje tačno. Pokazivač `13107360` = `0xC800A0` pada unutar fajla kao bajt-offset;
da li je u bajtovima ili sektorima još nije potvrđeno.

U poslednjem megabajtu TER2 ima **5041 blokova**, većinom `CONTAINER` po 208 B — regularna mreža tajlova.

### 6.4 Tipovi

| Kod | Znak | Širina | Značenje |
|---|---|---|---|
| `0x23` | `#` | 1 | u8 / mod |
| `0x24` | `$` | 3 | u24 |
| `0x25` | `%` | 4 | u32 |
| `0x34` | `4` | 3 | u24 |
| `0x35` | `5` | 4 | **koordinata, int32** |
| `0x37` | `7` | — | string/opis |
| `0x45` | `E` | 4 | float |

### 6.5 Koordinate

**`int32`, stepeni × 10⁷.**

Dokaz: `-120000000` i `790000000` na toj skali daju tačno okrugle `-12.0` i `79.0`. BAMS (2³²/360), 1e5 i 1e6 daju besmislice.

### 6.6 Korenski `CONTAINER` (TER2)

Deset kolona, red = 37 B:

```
TerrainIndexMode   1
WGSScaling         3.0        float
TerrainDepth       16
TerrainWidth       65536
TerrainHeight      65536
LongitudeBegin    -12.0000000°
LatitudeBegin      24.3858334°
LongitudeEnd       42.6141666°
LatitudeEnd        79.0000000°
ContainerSize      8192
```

Bounding box je **tačno kvadrat**, 54,6141666° po strani. Samoprovera:

```
54,6141666° × 3600 = 196611 arcsec
196611 / 3,0 (WGSScaling) = 65537 uzoraka = 65536 intervala = TerrainWidth
```

`WGSScaling` su dakle **lučne sekunde po uzorku**. Četiri nezavisna polja se poklapaju u cifru, pa alignment nije slučajan.

**`TER` je digitalni model terena:** mreža 65536×65536, 16 bita po uzorku (`TerrainDepth`), rezolucija 3 arcsec ≈ 93 m — SRTM3 klasa.

Ostala imena kolona viđena u šemi: `Heights`, `Errors`, `Radia`, `SoarTerrain`, `SoarTerrainDescription`.

### 6.8 Heder — potvrđen iz koda

`COrionDatabase::create` je **`FUN_08322504`** (2510 B) u `NavCore`. Iz njene dekompilacije,
struktura `SOrionDatabaseHeader_4_1`:

| Offset | Polje | Provera u kodu |
|---|---|---|
| `+0x00` | dužina Identification | |
| `+0x01` | `Identification` = `"HEADER"` | `memcmp("HEADER", hdr+1, len)` |
| `+0x10` | `Size` (u32) | `== 4096`, inače „Header size failed" |
| `+0x14` | `Version` major (u8) | grana `if (hdr[0x14] == 4)` |
| `+0x15` | `Version` minor (u8) | `<= 7` |
| `+0x16` | `Version` patch (u16) | |
| `+0x18` | `Endian` (char) | `== 'l'`, inače „Endian failed" |
| `+0x20` | dužina Engine | |
| `+0x21` | `Engine` = `"Orion"` | `memcmp("Orion", hdr+0x21, len)`, inače „Engine identification failed" |
| `+0x30` | ime baze = `"Atlas"` | iz `DataBaseInfo: name:%s` |

Kod ispisuje i `Header Version %lu.%lu.%lu` iz `hdr[0x14]`, `hdr[0x15]`, `*(u16*)(hdr+0x16)`.

Alat: `python3 atlas_blocks.py header "$ATLAS"` — parsira i pusti isti niz provera.

**Tri verzije formata žive u istom izdanju:**

| Verzija | Paketi |
|---|---|
| 4.2.1 | `TER`, `TER2`, `CTY`, `CTY2`, `CTY3` |
| 4.4.1 | `CTYS3TC`, `CTYS3TC2` |
| **5.1.1** | **`PSD`, `PSD2`, `PSD3`** |

Svih 10 `.ATLAS` fajlova prolazi sve provere. Bitno: **`PSD` — rutirajući graf, najvredniji paket —
koristi noviju verziju 5.1.1**, pa se šema ne sme slepo preneti sa `TER`-a. `NavCore` nosi
„Orion engine version 5.1.3", dakle podržava obe grane; postoji i `SOrionDatabaseHeader_1_1`
za stariju verziju 1.

---

### 6.7 Orion engine — C++ API iz binarnog fajla

U `NavCore` su ostala **puna C++ imena klasa i assertioni sa imenima polja**. Izvorno stablo:
`platform\common\isdb\orion\main\private\`. Engine se predstavlja kao **„Orion engine version 5.1.3"**.

Klase i ključne metode:

| Klasa | Metode |
|---|---|
| `COrionDatabase` | `create`, `validate`, `getContainer`, `getContainersInRange`, `closeResources`, `processInacessible` |
| `COrionIndex` | `create(SOrionDatabaseIndex&…)`, `resolveIndex`, `getContainer`, `getGeneric`, `getContainersInRange` |
| `COrionContainerBase` | `parseDescriptions`, `prepareDescriptions`, `createTables`, `loadIndexArray`, `createComposite`, `createObjects`, `readString`, `readBinary`, `calculateOffsets`, **`uncompress`** |
| `COrionContainerObject` | `create`, `createDescriptions`, `matchDescriptions` |
| `COrionGenericObject` | `create`, `copyGenericDescription` |
| Jobs | `COrionContainerJob`, `COrionIndexJob`, `COrionGenericJob` — svi `create`, `runJob`, `waitJob` |

Strukture: `SOrionDatabaseHeader_4_1`, `SOrionDatabaseHeader_1_1`, `SOrionDatabaseIndex`,
`SOrionContainerObjectCreation`.

**Potvrde hedera iz assertiona** (ovo više nisu pretpostavke):

```
DatabaseHeader->Identification == OrionDatabaseHeaderIdentification
SOrionDatabaseHeader_4_1->Endian == CHAR8C('l')
SOrionDatabaseHeader_4_1->Size   == 4096
SOrionDatabaseHeader_4_1->Engine == OrionDatabaseEngineIdentification
DatabaseRevision->Identification == OrionDatabaseRevisionIdentification
```

Poklapa se sa onim što smo pročitali iz fajla: na `0x10` stoji `00 10 00 00` = **4096** (`Size`),
a na `0x18` bajt `0x6c` = **`'l'`** (`Endian`, little). Dva nezavisna izvora se slažu.

**Adresiranje kontejnera** — iz potpisa:

```cpp
COrionContainerJob::create(UInt64 iOffset, UInt32 iSize, COrionDatabase&, COrionIndex*, …)
COrionIndexJob::create    (UInt64 iOffset, UInt32 iSize, …)
COrionGenericJob::create  (UInt64 iOffset, UInt32 iSize, …)
```

Dakle par **(offset `UInt64`, size `UInt32`)** — isti oblik kao `(*.ptr, *.size)` par koji smo
našli u listovima. Offset je **bajtni**, ne sektorski.

**Kompresija:** `COrionDatabase::mSqueezerZlibMutex` i `mSqueezerLzmaMutex` — payload se pakuje
**zlib** i **LZMA**, uz `COrionContainerBase::uncompress`. To objašnjava visoku entropiju
većine blokova uz strukturirane indekse u čistom.

Format info string: `AtlasDB - DataBaseInfo: name:%s, Orion version:%d.%d.%d, num containers: %d, block size %d`.

### 6.9 Blok kao jedinica — lanac preko `Size`

Svaki blok ima **isti prolog kao heder fajla**:

| Offset | Polje |
|---|---|
| `+0x00` | dužina imena, pa ime (`HEADER`, `CONTAINER`), popuna `0xCC` do 16 |
| `+0x10` | **`Size` (u32) — veličina ovog bloka** |
| `+0x14` | `Version` major / minor / patch (u8, u8, u16) |
| `+0x18`, `+0x1c` | dodatna polja |
| `+0x20` | telo bloka: `01`/`02` zapisi |

**`Size` je ujedno offset do sledećeg bloka.** Heder ima `Size = 4096`, pa prvi `CONTAINER`
stoji tačno na `0x1000`. Nije potrebno tražiti magic — lanac se šeta.

Alat: `python3 atlas_blocks.py walk "$ATLAS"`.

**Validacija — lanac pokriva svaki fajl tačno do kraja, u bajt:**

| Paket | Verzija | Blokova | Prosečan blok |
|---|---|---|---|
| `TER` | 4.2.1 | 733.399 | 2.727 B |
| `TER2` | 4.2.1 | 140.847 | 1.520 B |
| `CTY3` | 4.2.1 | 25.529 | 39.183 B |
| `CTYS3TC2` | 4.4.1 | 35.732 | 15.722 B |
| `PSD3` | **5.1.1** | 43.402 | 19.417 B |

Da je bilo koje polje `Size` pogrešno protumačeno, lanac bi se raspao davno pre kraja.
Ovo je najjača potvrda koju smo do sad imali — i **radi identično na verziji 5.1.1**,
dakle slaganje blokova ne zavisi od verzije formata.

### 6.10 Kompresija — `COrionContainerBase::uncompress`

Funkcija je **`FUN_0832f2e4`** (844 B). Iz dekompilacije, struktura kompresovanog bloka
(offseti u odnosu na učitani zapis):

```c
if ((byte)(hdr[0x20] - 2) < 2) {        // tip kompresije je 2 ili 3
    count = hdr[0x21];                   // broj delova
    if (count < 9) {                     // najviše 8 delova
        table = hdr + 0x22;              // niz parova po dva u32
        ...
    }
    squeezer = getSqueezer(hdr[0x20]);   // inače "no valid Squeezer instance found"
    total = 0x28;
    for each part: total += pair[i].second;
    buffer = alloc(total);               // inače "Cannot allocate a buffer of size %lu"
    memcpy(buffer, hdr, 0x24);           // prolog od 36 B se prenosi
}
```

Dakle: **bajt tipa bira kompresor, najviše 8 delova, po delu par veličina.**
Kompresori su `mSqueezerZlibMutex` i `mSqueezerLzmaMutex` — **zlib i LZMA**, oba u Python
stdlib-u (`zlib`, `lzma`). Kad se izoluje deo, raspakivanje je jedan poziv, ne novi reverse.

### 6.10a Raspakivanje je rešeno — LZMA1 raw

Struktura iz `uncompress` potvrđena je **na stvarnom fajlu**. Telo bloka:

```
+0x20  tip kompresije (2 ili 3)
+0x21  broj delova (1..8)
+0x22  tabela parova po dva u32: (kompresovano, raspakovano)
+0x22+8*n  kompresovani podaci
```

Primer, `PSD3` blok na `0x49ee80` (36800 B): `tip=3`, `delova=3`, par 0 = `(36717, 62909)`,
ostali parovi nule. Podaci na `+0x3a`.

**Parametri kompresije, utvrđeni empirijski i potvrđeni poklapanjem veličine u bajt:**

| Tip | Kompresor | Parametri |
|---|---|---|
| 3 | **LZMA1 raw** | `lc=3, lp=0, pb=2, dict_size=65536`, `FORMAT_RAW` |
| 2 | zlib / raw deflate | (viđen u kodu, u ovom izdanju nije naiđen) |

U Pythonu:

```python
lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[
    {"id": lzma.FILTER_LZMA1, "lc": 3, "lp": 0, "pb": 2, "dict_size": 1 << 16}])
```

Alat: `python3 atlas_blocks.py unpack "$ATLAS" [--out izlaz.bin]`.

**Rezultat po paketima:**

| Paket | Kompresovanih blokova | Odnos |
|---|---|---|
| `PSD3` | 2999 / 3000 | 1,95× |
| `PSD` | sve | 2,00× |
| `PSD2` | sve | 1,93× |
| `CTYS3TC2` | 899 / 1500 | 1,57× |
| `TER2`, `CTY3` | 0 — blokovi nisu kompresovani | — |

Na 3000 blokova `PSD3`: 3011 delova raspakovano, **1 neuspeh**. 41,6 MB → 81 MB.

### 6.10b Šema rutirajućeg grafa

Raspakovan sadržaj `PSD` je **isti zapis sa imenima** kao spoljni sloj — length-prefixed imena
kolona. Iz 2,2 MB raspakovanog `PSD3`:

```
CenterlineGeometry   PointGeometry   Longitude   Latitude   Segments   Offsets
Map   PointLlh   PointLld   Lane   Geometry   Parts   Item   Atom   Raw
Attributes   Properties   Identifiers   Urban   UrbanProperty
AudiUrbanProperty   AdasProperty   PropertyD1
EventAttributes   ZoneAttributes   ManoeuvrePart   AttributePart
```

`PointLlh` = Point Lat/Lon/**Height**, `PointLld` = varijanta sa drugom preciznošću.
`Longitude` i `Latitude` su imenovane kolone — ista mehanika koju već dekodiramo na `TER`-u.
`ManoeuvrePart` su skretanja, `AdasProperty` ADAS podaci, `AudiUrbanProperty` je proizvođačko
proširenje.

**Ovo je rečnik putne mreže.** Time je lanac od bajta u fajlu do imenovanog podatka o putu
zatvoren za `PSD`, najvredniji paket.

### 6.10c Zapisi u raspakovanom `PSD` — katalog

Raspakovan sadržaj je **tagovan katalog**: `<tag 01|02|03> <dužina> <ime> <payload>`,
gde je za tag 02/03 payload `u32 B + u8 C`, a za tag 01 `u16 A + u32 B + u8 C`.
`A = 65535` znači „nema", inače je indeks na drugi unos. `B` je broj elemenata.

```
tag  ime                              A       B    C
02   PointLlh                         -     383    3
02   PointLld                         -    1781    3
02   ClothoidCenterlineGeometryPart   -     580    1
01   PointGeometry                   16     383    1
01   AdasProperty                    11       1    1
01   SpeedLimitProperty              11       1    9
```

`PointGeometry` ima `B = 383` i pokazuje na unos 16, a `PointLlh` takođe ima 383 —
unosi se međusobno referenciraju preko indeksa.

Alat: `python3 atlas_blocks.py records raspakovano.bin`.

**Model putne mreže — 75 imena iz jednog uzorka od 2,2 MB:**

| Grupa | Imena |
|---|---|
| Graf | `RoadElement(s)`, `NodeRoadElement`, `EdgeRoadElement`, `From(s)`, `To(s)`, `Vias`, `Item(s)`, `ItemIndex`, `Atom` |
| Geometrija | `PointLlh`, `PointLld`, `PointGeometry`, `CenterlineGeometry`, `ClothoidCenterlineGeometry(Part)`, `Longitude`, `Latitude`, `Height`, `Position(s)`, `Segments`, `Offsets` |
| Atributi | `SpeedLimitProperty`, `NumberOfLanesProperty`, `PassingRestrictionProperty`, `SpeedBumpsProperty`, `AdasProperty`, `UrbanProperty`, `AudiUrbanProperty`, `LimitType`, `VehicleType`, `Unit`, `Speed`, `Direction`, `Orientation`, `Compliant` |
| Znakovi | `RegulationSign`, `DeregulationSign`, `Sign` |
| Vreme | `TimeDomain`, `TimeInformation`, `ValidityPeriod`, `Time` |
| Manevri | `Manoeuvre(s)`, `ManoeuvrePart` |
| Trake | `Lane(s)`, `Lefts`, `Rights`, `Passing` |
| Ostalo | `Map`, `Group`, `Type`, `Values`, `Raw`, `Zones`, `ZoneAttributes`, `Events`, `EventAttributes`, `Urban`, `Bumps`, `Normal`, `Identifiers`, `Properties`, `Parts`, `Attributes` |

`From` / `Vias` / `To` je klasičan zapis zabrane skretanja. `ClothoidCenterlineGeometry`
znači da se osa puta pamti kao **klotoida**, ne kao izlomljena linija — geometrija je
parametarska, što je bitno ako se ikad bude pisalo nazad.

### 6.10d Raspored je KOLONARAN — dokazano

Iza kataloga u raspakovanom sadržaju idu isti `02 <tip> <u32> 01` zapisi kao u spoljnom
sloju, ali `u32` ovde **nije širina ćelije nego veličina cele kolone u bajtovima**.

Dokaz — veličine se poklapaju sa brojevima elemenata iz kataloga, pet nezavisnih puta:

| Zapis | Veličina | Broj iz kataloga | Račun |
|---|---|---|---|
| `02 35` (koordinata) | 1208 B | `PointLlh` = 302 | 302 × 4 |
| `02 35` (koordinata) | 1208 B | `PointLlh` = 302 | 302 × 4 |
| `02 34` | 604 B | `PointLlh` = 302 | 302 × 2 |
| `02 35` (koordinata) | 14920 B | `PointLld` = 3730 | 3730 × 4 |
| `02 24` | 7460 B | `PointLld` = 3730 | 3730 × 2 |
| `02 23` | 393 B | `ClothoidCenterlineGeometryPart` = 393 | 393 × 1 |

Dakle `PointLlh` nije niz od 302 sloga po 12 B, nego **tri kolone**: 302 × `int32` širine,
302 × `int32` dužine, 302 × `u16` visine, svaka smeštena kontinuirano.

To objašnjava zašto traženje isprepletanih `(lat, lon)` parova nije moglo da uspe —
koordinate nisu jedna do druge.

**Granica dokle se stiglo empirijski.** Ni čitanje kolone kao apsolutnih `int32 × 10⁷`
ni prosto delta kodiranje ne daju koherentan niz ni na jednom probanom početku
(pretraženo 200 offseta). Zbir veličina kolona je 48.398 B, a iza zaglavlja stoji
60.816 B — **12.418 B razlike**, što znači da kolone nisu prosto poređane redom.

Gde su — računa **`COrionContainerBase::calculateOffsets`** (`FUN_0832ead8`, 1830 B).
Ime funkcije doslovno opisuje ono što nedostaje. Ovo je tačka gde dalje pogađanje
nema smisla i gde se mora pročitati ta funkcija.

### 6.10e Zašto kolone nisu čitljive kao obični nizovi

`calculateOffsets` i `OrionGet.cpp` otkrivaju sloj koji je nedostajao. Postoje **četiri
načina pristupa koloni**, i svaka kolona nosi svoj:

| Klasa | Adresiranje | Vrednosti |
|---|---|---|
| `CBytePlainDecompression` | bajt | neupakovane |
| `CByteBitDecompression` | bajt | **bitovno pakovane** |
| `CBitPlainDecompression` | bit | neupakovane |
| `CBitBitDecompression` | bit | **bitovno pakovane** |

Izbor pravi `CDecompression::create`, koja na nepoznatu vrednost javlja
`Unknown compression type: %d`.

Assertioni koji to potvrđuju:

```
CByteBitDecompression::read :  ((iOffset & 0x7) == 0)          "offset has brocken bit alignment"
CBitBitDecompression::read  :  ((iOffset & (STypeTrait<EType>::Width - 1)) == 0)
```

**Offseti su u bitovima**, a poravnanje se traži na `STypeTrait<EType>::Width` — širinu tipa.

Time je objašnjeno sve što nije htelo da se dekodira: kolona koordinata ne mora biti niz
`int32` na bajt granici. Može biti spakovana na proizvoljan broj bita po vrednosti, na
bitovnom offsetu. Zato ni apsolutno čitanje ni prosto delta kodiranje nisu mogli da prođu —
greška nije bila u skali nego u pretpostavci da su vrednosti bajtovno poravnate.

Tipski sistem iz `calculateOffsets`: `Type_Structure` (`0xc0`), `Type_Array`,
`Kind_Structure` (2), `Kind_Array` (3), uz provere `MemberComposite < Composite`
(zabrana unapred-referenci) i `BaseComposite->Kind == Kind_Class`.
Polja člana: tip na `+0x01`, širina `u16` na `+0x14`, offset `u32` na `+0x18`;
kod kompozita širina na `+0x56`, offset na `+0x58`, podrazumevana širina 8.

Kompresori su potvrđeni i imenom: `CSqueezerLzma` i `CSqueezerZLib`, u
`platform\common\isdb\squeezer\private\`.

### 6.10f `CDecompression::create` — tri koda i bitovni dekoder

Funkcija je **`FUN_083319e8`** (178 B). Selektor je trivijalan:

```c
if (param_1 == 2)  -> FUN_08331050
else if (p1 == 1)  -> FUN_08330224
else if (p1 == 3)  -> FUN_08331740
else               -> "Unknown compression type: %d"
```

Dakle **kodovi kompresije kolone su 1, 2 i 3** (0 se ne pojavljuje ovde — verovatno
znači „bez dekodera", tj. `CBytePlain`).

**Tipovi 1 i 2** (`FUN_08330224`, `FUN_08331050`, oba 358 B) su dispečeri po **kodu tipa
elementa**, sa granama na `0x10`, `0x20`, `0x22`, `0x30`. To je ista familija kodova kao
tipovi kolona koje već vidimo u fajlu (`0x23`, `0x24`, `0x25`, `0x34`, `0x35`, `0x45`) —
gornji nibl je kategorija, donji varijanta/širina.

**Tip 3** (`FUN_08331740`, 608 B) je stvarni **bitovni dekoder**. Alocira stanje od `0x28`
bajta i sklapa vrednosti pomeranjem:

```c
uVar10 = uVar10 | uVar8 << (uVar1 & 0x1f);
*(short *)(iVar4 + 8) = (short)((int)((uVar10 & 0x1f) << 0xb) >> 0xb) + 1;
```

Onaj izraz `(x & 0x1f) << 0xb >> 0xb` je **znakovno proširenje petobitnog polja**, pa `+1`.
Dakle dekoder iz strima čita **širinu u bitovima zapisanu u 5 bita**, i onda vrednosti
raspakuje na toj širini.

To je konkretan mehanizam bitovnog pakovanja: širina nije fiksna po tipu nego se **čita iz
samog strima**, po koloni, kao 5-bitno polje uvećano za jedan (opseg 1..32 bita).

### 6.10g Bitovni čitač i jedna ispravka

`atlas_bits.py` implementira čitač iz `FUN_08331740`: LSB-first unutar little-endian `u32`
reči, zaglavlje od 5 bita nosi širinu. Verifikovan je na sopstveno spakovanim podacima —
širine 7, 12, 21 i 32 bita, sve četiri se čitaju tačno nazad.

```bash
python3 atlas_bits.py read /tmp/one.bin --offset 0x82d --count 302
python3 atlas_bits.py probe /tmp/one.bin --count 302 --degrees
```

Napomena o širini: kod je **znakovno proširuje** (`sign_extend_5(v) + 1`), što daje opseg
−15..16 i ne može da predstavi širine preko 16. Negativna vrednost je verovatno oznaka
posebnog slučaja, ne širina. Alat podržava oba čitanja preko `--width-mode`.

**Ispravka ranije pretpostavke.** Kolone koordinata **nisu bitovno pakovane.** Odnos
deklarisane veličine i broja elemenata je ceo broj bajtova:

| Tip | Veličina | Elemenata | B/elem |
|---|---|---|---|
| `'5'` | 1208 | 302 | **4** |
| `'5'` | 14920 | 3730 | **4** |
| `'4'` | 604 | 302 | 2 |
| `'$'` | 7460 | 3730 | 2 |
| `'#'` | 393 | 393 | 1 |

Bitovno pakovanje važi samo za deo kolona (one čija veličina nije umnožak broja elemenata).
Problem sa koordinatama nikad nije bio u kodiranju nego u **položaju**.

### 6.10h Gde podaci NISU — negativan rezultat koji menja model

Iscrpna pretraga celog raspakovanog dela (62.909 B, svaki 4-bajtno poravnat offset):

| Hipoteza | Rezultat |
|---|---|
| 302 uzastopnih `int32` kao apsolutna širina (24..79°) | **0 pogodaka** |
| 302 uzastopnih `int32` kao apsolutna dužina (−12..42,7°) | **0 pogodaka** |
| 302 `int32` kao delte, kumulativ unutar 0,5° | **0 pogodaka** |
| isto za 3730 (`PointLld`) | **0 pogodaka** |

Nijedna varijanta ne postoji u tom bloku. Zaključak: **raspakovani blok je deskriptor, a ne
nosilac podataka.** Kolone su opisane ovde, ali njihov sadržaj živi u drugim blokovima fajla,
adresiranim parom `(UInt64 offset, UInt32 size)` — tačno onim iz potpisa
`COrionContainerJob::create`.

To se slaže sa svime ranijim: `calculateOffsets` postoji baš zato da izračuna gde je koja
kolona, a mi smo je tražili unutar indeksa.

### 6.10i PRVE STVARNE KOORDINATE

Podaci **jesu** u raspakovanom sadržaju — samo ne u onom bloku koji sam prvo testirao.
Nad ispisom više blokova (`unpack --out`) nađene su kolone koordinata.

Uzorak iz kolone širine na `0x0f0aa8` (2032 vrednosti):

```
53.8637000  53.8637259  53.8638432  53.8639900  53.8640700  53.8640839
```

Sedam decimala, realne vrednosti, pomešane zaokružene i pune preciznosti — potpis stvarnih
kartografskih podataka.

**Raspored:** kolone su `int32`, skala `10⁻⁷`, složene **uzastopno u trojkama iste dužine**.
Primeri: 479/479/479 na `0x0ed474`, 2032/2032 na `0x0eeae8`, 318/318 na `0x0b4b9c`.
To odgovara `PointLlh` = dužina, širina, visina.

**Tajl je stepen dvojke.** Raspon svake kolone je najviše **`2^18` jedinica = 0,0262144°**
(≈ 2,9 km). Ponavlja se tačno kod svih nađenih kolona.

Alat: `python3 atlas_blocks.py tiles raspakovano.bin`.

**Nerešeno: pomak kolone dužine.** Prateća kolona ima iste osobine (isti raspon `2^18`,
isti potpis zaokruživanja: `86.6296800`, `86.6299700`), ali vrednosti su oko `86°`.
Uz pomak od 80° dobija se `6,6°`, što uz širinu `53,85°` pada u Severno more, a treća
kolona daje visine 34–41 m — nespojivo sa morem. Dakle **pomak od 80 nije tačan**.

Pokušaj da se pomak izmeri iz opsega pokrivenosti nije uspeo: raspodela `int32` vrednosti
je preširoka, pa filtri seku umesto da otkriju prirodne granice. Pomak treba izvesti iz
koda ili iz poznate tačke, ne iz statistike.

### 6.10j Mreža tajlova je poravnata na nulu — i to ograničava pomak

Ranije merenje pomaka bilo je pogrešno: sabirao sam **sve `int32` iz fajla** koji padnu u
neki opseg, pa su granice ispale tačno na mojim filterima. Ispravno je uzeti **samo
vrednosti iz kolona koje je detektor već potvrdio**.

Alat: `python3 atlas_blocks.py stats raspakovano.bin`.

**Rezultat: minimumi kolona padaju TAČNO na granice mreže `k × 2^18`.**

| Vrednost | Rastavljeno |
|---|---|
| `53.8443776` | `2054 × 2^18 + 0` |
| `86.6123776` | `3304 × 2^18 + 0` |
| `86.6385920` | `3305 × 2^18 + 0` |
| `53.6870912` (globalni min) | `2048 × 2^18 + 0` = **tačno `2^29`** |

Ostatak je nula u svakom slučaju. Dakle **ishodište mreže je 0**, ćelija je `2^18` jedinica
(`0,0262144°`), i **svaka kolona pokriva tačno jednu ćeliju** — kolone su po tajlu.

**Posledica koja rešava pola pitanja o pomaku.** Ako obe ose moraju ostati poravnate na
`2^18`, onda pomak mora biti **umnožak `2^18`**. A `80°` = 800.000.000 jedinica, što je
`3051,7578 × 2^18` — **nije umnožak**. Time je moja ranija pretpostavka od 80° isključena
strukturnim argumentom, ne procenom.

Najbliži dozvoljeni kandidati: `3051 × 2^18 = 79,9801344°` i `3052 × 2^18 = 80,0063488°`.

Pomak je i dalje nepoznat, ali više nije proizvoljan broj — mora biti celobrojni umnožak
veličine ćelije.

### 6.10k Merenje na celom `PSD3` — hipoteza o pomaku ne stoji

Raspakovan je **ceo `PSD3`**: 42.081 od 42.916 delova (2% neuspeha), 803 MB → 1,52 GB.
Nad 380 miliona vrednosti izmerena je raspodela minimuma kolona, **bez ijednog filtera
opsega** (raniji pokušaji su merili sopstvene granice filtera):

```
   0.00 ..   5.33   1110   ##########            <- kolone visina
  42.61 ..  74.58  14377   ############...###    <- SIRINA, evropske vrednosti
  79.90 .. 143.82   9000+  ####...####           <- druga kolona
```

Klaster širine `42,6–74,6°` je nedvosmisleno geografski. Napomena: `PSD3` je treći deo
kontejnera, pa pokriva samo severni isečak Evrope — otud nedostatak vrednosti ispod 42,6°.

**Hipoteza „druga kolona = dužina + konstanta" ne prolazi.** Iz granica klastera:

| Iz čega | Traženi pomak |
|---|---|
| min `79,90` treba da bude dužina `−12` | `B = 91,9` |
| max `143,82` treba da bude dužina `42,6` | `B = 101,2` |

Dve granice traže **različit pomak**, pa jedne konstante nema. Uz to je klaster širok
`63,9°`, dok je dužinski opseg Evrope `54,6°`.

**Kontraargument iz već rešenog dela.** U `TER`-u je dužina zapisana **direktno i sa
znakom**: `LongitudeBegin = −120000000` = `−12,0°`, bez ikakvog pomaka (sekcija 6.6).
Nema razloga da isti engine u `PSD`-u pomera osu.

**Zaključak:** druga kolona verovatno **nije dužina**. Identifikaciju treba izvesti iz
kataloga — povezati redosled kolona sa imenima (`PointLlh` = dužina, širina, visina) preko
`calculateOffsets`, umesto pogađati po opsegu vrednosti.

### 6.10l `calculateOffsets` — raspored JESTE sekvencijalan

Iz dekompilacije `FUN_0832ead8`, jezgro petlje:

```c
*(int *)(member + 12) = running;                       // member->offset = tekuci
running = running + ((*(int *)(member + 8) + 7) >> 3); // += ceil(bitovi / 8)
```

Dakle **kolone se ređaju jedna za drugom**, a svaka pomera pokazivač za
`ceil(veličina_u_bitovima / 8)` bajta. Zaokruživanje naviše na ceo bajt objašnjava zašto
prost zbir deklarisanih veličina ne mora da se poklopi sa razmakom.

> **Ispravka sekcije 6.10h.** Tamo sam zaključio da kolone „nisu prosto poređane redom" na
> osnovu razlike od 12.418 B između zbira veličina i dostupnog prostora. Taj zaključak je
> bio preuranjen — zbir je bio nepotpun (moj parser nije pokupio sve `02` zapise), a
> zaokruživanje po koloni dodatno pomera račun. Raspored je sekvencijalan.

**Polja člana** (indeksiranje kao `ushort*`, pa su pomaci u bajtovima):

| Bajt | Značenje |
|---|---|
| `+0` | granularnost poravnanja (u16) |
| `+4` | broj značajnih bitova, izračunat iz maske |
| `+8` | veličina u bitovima |
| `+12` | **offset podataka** — ovo je rezultat funkcije |
| `+16` | veličina zaokružena naviše na granularnost |

**Maska.** Svaka kolona ima niz maski koji kaže koji su bitovi stvarno u upotrebi.
Funkcija traži **najviši postavljeni bit**: uzme bajt na `bitovi >> 3`, primeni masku
`(1 << (bitovi & 7)) - 1`, a ako ispadne nula, silazi unazad do prvog bajta različitog od
nule, pa prebroji vodeće nule. Rezultat `bajt_indeks * 8 + pozicija` je stvarni broj
značajnih bitova. Ako je adresa maske nula, javlja `Zero mask address`.

To znači da **deklarisani tip nije i stvarna širina** — širina se izvodi iz maske po koloni.
Zbog toga nijedno čitanje sa fiksnom širinom nije moglo da pogodi raspored.

### 6.10m Raspored POTVRĐEN na podacima — kolone vezane za imena

Pravilo iz `calculateOffsets` provereno je tako što je nezavisno poznato gde je kolona
širine (detektor je nalazi po vrednostima), pa je provereno da li je sekvencijalni raspored
pogađa.

**Rezultat, tri nezavisna bloka:**

| Blok | Šema se završava | Baza podataka | Kolona `#4` tipa `'5'` pada na | Detektovana širina na |
|---|---|---|---|---|
| `0x1000` | `0x730` | `0x772` | `0x323c` | `0x323c` |
| `0x70a0` | `0x730` | `0x772` | `0x3708` | `0x3708` |
| `0xfb00` | `0x730` | `0x772` | `0x2600` | `0x2600` |

Pogađa **tačno u bajt**, tri puta. Raspored je time potvrđen na podacima, ne samo pročitan
iz koda.

**Vezivanje kolona za imena.** Redosled kolona odgovara redosledu imena u katalogu:

```
 #  tip  velicina   sadrzaj
 0  '5'      1532   86.3498500, 86.3494400, 86.3451500   \
 1  '5'      1532   54.3687100, 54.3713300, 54.3929200    >  PointLlh  (383 x 4 = 1532)
 2  '4'       766   18961, 20156, 17300                  /
 3  '5'      7124   86.3317700, 86.3310709, 86.3306600   \
 4  '5'      7124   54.3745000, 54.3750104, 54.3753800    >  PointLld  (1781 x 4 = 7124)
 5  '$'      3562   24803, 22586, 22207                  /
```

Brojevi elemenata iz kataloga (`PointLlh = 383`, `PointLld = 1781`) poklapaju se sa
veličinama podeljenim sa 4. **Trojka je time imenovana**, a kolona `1` je nedvosmisleno
širina.

**Baza podataka** je kraj šeme uvećan za `0x42` (66 B) — niz zastavica po koloni plus
poravnanje. Kod ova tri bloka šema se završava na istom mestu jer im je katalog gotovo
identičan; kod blokova sa drugačijom šemom bazu treba računati, ne uzimati fiksno.

**Kolona `0` i dalje nije identifikovana.** Uzorkovanje kroz 3176 blokova sa *fiksnom*
bazom `0x772` daje pretežno smeće (raspon `−214 .. 213`), jer baza nije ista svuda.
Verodostojni uzorci koji su izašli: `(86,35 / 54,37)` i `(97,33 / 57,44)`. Uz pomak 80 to
daje `6,35°E / 54,37°N` i `17,33°E / 57,44°N` — obe tačke padaju na more, što i dalje ne
potvrđuje pomak. Sledeći korak je računati bazu po bloku pa ponoviti uzorkovanje.

### 6.10n Pomak je ≈ 80° — i ispravka mog ranijeg argumenta

Baza podataka se ne može izvesti iz broja kolona (blokovi sa 34 i 35 kolona imaju isti
razmak od 66 B). Zato se **traži po bloku**: proba se svaka baza dok kolona `1` ne da
uverljive širine, pa se sa istim rasporedom čita kolona `0`.

Rezultat na **1701 čistih parova** iz 1779 blokova:

| Kolona | Opseg |
|---|---|
| `0` | `80,857 .. 117,344` |
| `1` (širina) | `49,583 .. 71,983` |

Uz pomak 80° kolona `0` daje dužine `0,86 .. 37,34 E`, uz širine `49,58 .. 71,98 N` —
od Francuske/Beneluksa do istočne Ukrajine i severne Norveške. To je koherentan isečak
Evrope, saglasan sa tim da je `PSD3` treći deo kontejnera.

**Provera na poznatim tačkama:**

| Uzorak uz pomak 80 | Najbliži grad |
|---|---|
| `12,7680 E / 56,0821 N` | Kopenhagen `12,57 E / 55,68 N` |
| `12,8056 E / 56,0011 N` | isto |
| `36,6490 E / 50,1355 N` | Harkov `36,23 E / 49,99 N` |
| `37,3438 E / 49,6645 N` | isto područje |

> **Ispravka sekcije 6.10j.** Tamo sam tvrdio da pomak **mora** biti umnožak `2^18`, jer
> minimumi kolona padaju tačno na `k × 2^18`. To je bila greška u rezonovanju: poravnate su
> **zapisane** vrednosti, a ne stvarne koordinate. Ako je `zapisano = stvarno + B`, ništa ne
> zahteva da i stvarne koordinate budu poravnate na mrežu. Pomak od tačno `80°` time nije
> isključen — moj argument protiv njega nije važio.

> **Ispravka sekcije 6.10k.** Tamo sam odbacio hipotezu o pomaku jer su granice tražile
> `91,9` i `101,2`. Ta računica je pretpostavljala da `PSD3` pokriva **ceo** evropski
> bounding box. Ne pokriva — treći je deo od tri. Test je bio nevažeći.

**Status:** pomak `≈ 80°` je dobro potkrepljen sa dve nezavisne poznate tačke i koherentnim
opsegom. Tačna vrednost nije određena preciznije od `±0,1°`, jer uzorci nisu vezani za
konkretan objekat na terenu. Za tačnu vrednost treba naći konstantu u kodu ili uporediti
poznatu deonicu puta.

### 6.10o Izvoz u GeoJSON — prvi opipljiv rezultat

`atlas_export.py` sklapa ceo lanac: šetanje blokova → LZMA → katalog → šema → baza po bloku
→ kolone → tačke.

```bash
python3 atlas_export.py list   "$ATLAS" --limit 12
python3 atlas_export.py export "$ATLAS" --out t.geojson --lat0 54 --lat1 56.5 --lon0 11 --lon1 13.5
```

Baza se traži po bloku (ne da se izvesti iz broja kolona), pomak se zadaje preko `--bias`
da bi se preklapanjem sa pravom podlogom doterao.

**Rezultat na `PSD3`:** 2271 validnih tajlova, **602.136 tačaka**, pokrivenost
`lon 0,57 .. 97,98`, `lat 42,57 .. 72,83` (uz pomak 80).

Izvezena dva gusta klastera:

| Fajl | Tačaka | Područje |
|---|---|---|
| `klaster_12E.geojson` | 442.879 | `11–13,5 E`, `54–56,5 N` |
| `klaster_6E.geojson` | 367.129 | `5,5–7,5 E`, `53,7–55 N` |

Uzorkovane verzije po 12.000 tačaka (`uzorak_12E`, `uzorak_6E`) staju u `geojson.io`.

**Otvorena pitanja koja izvoz otkriva:**

- Gornja granica dužine ide do `97,98 E`, što je izvan ECE regiona. Deo tajlova verovatno
  ima pogrešno pogođenu bazu, pa daje besmislene koordinate uprkos filtru raspona.
- Gustina u klasteru `12E` koncentrisana je u pojasu `55,9–56,2 N`, `12,4–13,5 E`, a ispod
  je retko. Liči na kopno i obalu, ali to je moja procena iz gustinske mape, **ne provera**.

**Vizuelna provera preko prave podloge je jedina koja vredi** — dok se ne uradi, pomak od
80° ostaje potkrepljen sa dve tačke, ne potvrđen.

### 6.10p Vizuelna provera — dodela kolona potvrđena, pomak nije

Prva provera preko prave podloge (`uzorak_6E.geojson` na `geojson.io`): tačke formiraju
**kompaktan, jasno ograničen oblak** — dakle nije šum — ali padaju u **Vatensko more severno
od Groningena**, dok je kopno ispod njih.

**Dodela kolona je time potvrđena, i to nezavisno od mojih pretpostavki.** U bloku `0x1000`
postoje samo dva para koordinatnih kolona, sa jasno različitim rasponima:

| Kolona | Raspon tajla | = |
|---|---|---|
| `0`, `3` (≈86°) | `0,0524288°` | `2^19` |
| `1`, `4` (≈54°) | `0,0262144°` | `2^18` |

Dužinske ćelije su **tačno dvostruko šire** od širinskih — standardna kompenzacija za
`cos(širine)` (odnos 2 odgovara projektovanju oko 60°). Kolona sa širim ćelijama je dužina.
To ne zavisi od opsega vrednosti, pa nije podložno grešci koju sam napravio u `find_base`,
gde sam **zahtevao** da kolona `1` bude u opsegu 24–79° i time sam sebi nametnuo odgovor.

**Pomak nije rešen.** Dve kontradiktorne indicije:

| Indicija | Sugeriše |
|---|---|
| Uzorak kod Harkova `(116,65 / 50,14)` → `36,65 E` uz Harkov `36,23 E` | pomak ≈ 80 |
| Oblak kod Groningena je ~1,2° preseveran, ili ~2–4° prezapadan | pomak 76–78, ili korekcija širine |

Generisani su kandidati za vizuelnu proveru: `pomak_74/76/78/80.geojson` i
`pomak_sirina.geojson` (širina −1,17°), svaki po 5.000 tačaka.

**Metodološka napomena.** Do sad sam tri puta doneo zaključak o pomaku iz unutrašnje
konzistentnosti i sva tri puta pogrešio. Odluka se prenosi na vizuelnu proveru preko
nezavisne podloge, jer je to jedini izvor istine koji nije izveden iz samih podataka.

### 6.10q POTVRĐENO: dekodirani podaci su stvarna putna mreža

`uzorak_gust.geojson` (80.118 tačaka iz **jednog bloka**, `0x1175cf0`) otvoren na uvećanju
pokazuje **jasne linijske strukture — ulice, raskrsnice i zgusnuta jezgra naselja**.

To je konačna potvrda celog lanca:

```
fajl -> blokovi preko Size -> LZMA1 raw -> katalog -> sema -> baza po bloku
     -> kolone -> (dužina, širina) int32 x 1e-7 -> putna mreža
```

Nijedan korak nije pogrešan, jer bi bilo koja greška u lancu dala šum umesto puteva.

**Preostaje samo georeferenca.** Uzorak pada preko Øresunda kod Helsingborga — blizu, ali
ne na kopnu. Napravljen fini raspon `fino_79_6/79_7/79_8/79_9.geojson` (koraci od `0,1°`).

**Radna hipoteza o uzroku raštrkanosti.** Ranije neuspele provere (tačke u moru severno od
Groningena, 5–13% tačaka u otvorenom moru bez obzira na pomak) verovatno **nisu posledica
pogrešnog pomaka nego nepouzdanog `find_base`**. Blokovi kojima je baza tačno pogođena daju
koherentnu mrežu na skoro tačnom mestu; blokovi sa promašenom bazom daju pomerene tačke.
Jedan globalni pomak ne može da popravi mešavinu, što objašnjava zašto nijedan kandidat
nije dao dobar odnos kopno/voda.

Sledeće: pooštriti `find_base` (npr. zahtevati da i kolona `0` ima raspon `2^19`), pa
ponoviti merenje pomaka samo na blokovima sa pouzdanom bazom.

### 6.10r Pomak izmeren: ≈ 78,25°

**Strogi `find_base`.** Ranija verzija je proveravala samo kolonu `1` i tražila da bude u
opsegu 24–79°, čime je sama sebi nametala koja je kolona širina. Stroga verzija koristi
geometriju mreže, utvrđenu nezavisno: dužina se drži ćelije `2^19`, širina ćelije `2^18`,
i **obe moraju ležati unutar jedne ćelije poravnate na nulu**.

Efekat: 2618 → **1520 tajlova** (2,25M tačaka). Odbačeni su blokovi sa promašenom bazom,
koji su ranije zamućivali svako merenje pomaka.

**Merenje pomaka brojanjem pogodaka.** Putevi ne postoje na otvorenom moru, a gusti su u
gradovima. Za svaki kandidat broje se tačke u poznatim pravougaonicima:

| Pomak | Tačaka u gradovima | Tačaka u otvorenom moru |
|---|---|---|
| `80,0` | 133 | 226.478 |
| `79,0` | 20 | 104.554 |
| **`78,2`** | **3.198** | 4.333 |
| **`78,3`** | **2.993** | 3.669 |
| `78,5` | 63 | 8.116 |
| `77,0` | 28 | 4.299 |

Vrh je **oštar i lokalizovan** — u pojasu `78,1–78,3` broj tačaka na kopnu je 20–100× veći
nego bilo gde drugde, uz istovremeno najmanju vodu.

**Provera drugim skupom gradova.** Prvi vrh je dolazio samo od Kijeva, što nije dokaz. Test
je ponovljen sa deset istočnoevropskih gradova: maksimum je na **`78,29`**, gde se pogađaju
**Kijev (162 tačke) i Minsk (597)**. Ostalih osam ostaje na nuli — `PSD3` ih verovatno ne
pokriva, pošto je treći deo kontejnera.

**Zaključak: pomak ≈ 78,25 ± 0,05.** Tri nezavisna puta daju isto:

1. brojanje kopno/voda na strogo filtriranim tajlovima
2. pogađanje gradova iz drugog skupa
3. vizuelna provera (`pomak_78` seda na Šlezvig-Holštajn)

Ranija procena od 80° bila je pogrešna za ~1,75°, što je oko 110 km — dovoljno da tačke
padnu u more i da me tri puta odvede na pogrešan trag.

### 6.10s POTVRĐENO NA GRADU — čitanje `PSD`-a je završeno

Izvoz sa pomakom `78,25` nad Minskom (`minsk_78_25.geojson`, 2540 tačaka iz jednog tajla)
pada **na kopno, na severne prilaze gradu** (Barauliany, Uručča, Zaslaŭje), a tačke prate
putne pravce.

Time je ceo lanac potvrđen spolja, na nezavisnoj podlozi:

```
.ATLAS fajl
  -> blokovi preko Size na +0x10
  -> LZMA1 raw (lc=3 lp=0 pb=2, dict 64K)
  -> katalog imena + sema `02 <tip> <velicina> 01`
  -> baza po bloku (obe kolone u svojoj celiji: 2^19 / 2^18)
  -> kolone int32, skala 1e-7, dužina uz pomak ~78,25
  -> putna mreža na pravom mestu
```

**Potvrda na Kijevu** (`kijev_78_25.geojson`) je najjača: izvezene tačke iscrtavaju
prepoznatljive stvarne saobraćajnice — liniju uz desnu obalu Dnjepra kroz Podil/Pečersk
(Naberežno šose), **zatvoren prsten obilaznice** kod Čabana i Novosilki, i krak ka
aerodromu Borispolj. Zatvoren prsten na pravom mestu ne može nastati slučajno.

**Poznata greška: visine.** U izvozu kolona `h` daje niz `52125, 0, 53586, 0, 53715, 0…`.
Naizmenične nule su potpis čitanja **`u32` kolone kao `u16`**. Ali u kijevskom bloku
(`0x20dfb40`) nula nema — vrednosti idu `6025, 5956, 5975, 5006, 4428, 9796, 20965…`.
Dakle **treća kolona nije istog tipa u svim blokovima**, pa je `read_triple` fiksira
pogrešno. Visine **nisu pouzdane**; koordinate jesu, jer su čitane kao `int32` i potvrđene
na mapi.

### 6.11 Adrese metoda u `NavCore`

| Metoda | Funkcija | Veličina |
|---|---|---|
| `COrionDatabase::create` | `FUN_08322504` | 2510 B |
| `COrionContainerBase::parseDescriptions` | `FUN_0832c064` | 4540 B |
| `COrionContainerBase::createTables` | `FUN_0832d65c` | 994 B |
| `COrionContainerBase::loadIndexArray` | `FUN_0832da88` | 460 B |
| `COrionContainerBase::readString` | `FUN_0832e6a0` | 74 B |
| `COrionContainerBase::readBinary` | `FUN_0832e6f4` | 78 B |
| `COrionContainerBase::calculateOffsets` | `FUN_0832ead8` | 1830 B |
| `COrionContainerBase::uncompress` | `FUN_0832f2e4` | 844 B |

Nađene su preko tabele deskriptora na `0x08500340`–`0x085003f0` (parovi *fajl, metoda*
po 12 B), pa traženjem koda koji čita te slotove.

---

## 6.12 Lanac provera integriteta

Provere ne izvodi `NavCore` nego **`/usr/bin/vdev-logvolmgr`** (240 KB, SH4, strippovan) —
menadžer koji obrađuje SD update. Uvezen je u zaseban Ghidra projekat `ghidra_proj2`.
Ključna funkcija je **`FUN_08045440`** (1808 B), parser `.conf` fajla.

### Šta je reprodukovano

| Polje | Značenje | Status |
|---|---|---|
| `MD5=` | MD5 celog fajla | **reprodukovano**, poklapa se |
| `check=qa,100,<a>,<b>,<c>` — prvi | MD5 **prvih 100 KB** (102400 B) | **reprodukovano** |
| `check` — drugi | MD5 **100 KB na `size//2`** | **reprodukovano** |
| `check` — treći | nepoznat isečak | nije |
| `checkcrc=` | CRC nad `.conf`-om | mehanizam poznat, algoritam ne |
| `size=` | veličina fajla | trivijalno |

Treći MD5 nije prost blok — pretražen je ceo fajl na rasteru od 1 MB i okolina kraja na
2048 B, bez pogotka.

### `checkcrc` — mehanizam

Iz `FUN_08045440`, grana `case 0xb` obrađuje ključnu reč `checkcrc`:

```c
uVar8 = strtoul(vrednost, 0, 0x10);       // heks
*(u32 *)(param_2 + 0x38) = uVar8;         // zapamti procitanu vrednost
... "skipping line [%s], CRC"             // linija se PRESKACE iz obracuna
```

Poređenje je `*(int *)(param_2 + 0x3c) == *(int *)(param_2 + 0x38)` — izračunato prema
pročitanom. Dakle CRC ide nad `.conf`-om **bez `checkcrc` linije**.

Isprobano bez pogotka: `zlib.crc32`, CRC-32/BZIP2, Adler-32, prosta suma, djb2, uz pet
varijanti završetaka linija. U binarnom fajlu **nema CRC tabele**, pa se računa bitovno ili
dolazi iz biblioteke. Postoji i druga ključna reč `fdefcrc`.

### Zašto to ipak nije prepreka

Iz same pomoći alata:

> „The file definition must contain either a crc or md5 field.
> **Md5 is preferred, while CRC32 is for testing only.**"

Dakle za temeljnu proveru **MD5 je primaran, a CRC32 je samo za testiranje**. Za pisanje
nazad dovoljno je dati ispravan `MD5=`, koji umemo da izračunamo. Brza provera (`-Q`) je
opciona, a i od nje su dva od tri elementa reprodukovana.

**Procena rizika za cilj A: znatno niža nego što se činilo.** Lanac provera nije zid.

### 6.12a Ima li internih provera u `.ATLAS`-u — ne

Dva nezavisna testa, oba negativna.

**1. Stringovi u Orion zoni.** U celom opsegu `0x084fc000–0x08506000` postoje samo dva
pogotka na `crc|checksum|digest|md5|verif|corrupt`:

- `--> got corrupted data after compression->decompression!!!` — samotest kompresora
- `header crc mismatch` — **to je zlib-ova poruka**, ne Orion provera. Okolo nje stoji cela
  `inflate.c` tabela grešaka (`incorrect header check`, `invalid block type`,
  `invalid distance too far back`…). Lažna uzbuna.

**2. Šesnaest bajtova pred terminatorom bloka.** Provereno na 400 blokova: najčešće
vrednosti su `00 cc cc cc…`, dakle **obična `0xCC` popuna**, a raznolikost dolazi od
podataka koji se prelivaju u to polje. Nijedna MD5 varijanta bloka se ne poklapa. Nije
digest.

**Zaključak: `.ATLAS` nema interne kontrolne sume.** Integritet se proverava isključivo
spolja — `.conf` (MD5, quick check, CRC) i `metainfo2.txt`.

> Ograda: odsustvo poruke o grešci nije apsolutan dokaz — suma se može računati i bez
> ijednog stringa. Ali uz nalaz da u bloku nema polja za digest, dokaz je jak.

### 6.12c Test ponovnog pakovanja

Uzeto 399 blokova `PSD3`, raspakovano pa spakovano nazad istim LZMA parametrima
(`lc=3, lp=0, pb=2, dict=64K`, `FORMAT_RAW`).

| Rezultat | Broj |
|---|---|
| bajt-identično sa originalom | **0** |
| različito, ali se ispravno raspakuje nazad | **399** |

**Naš izlaz je uvek validan** — dekompresija vraća tačno isti sadržaj. Original je pakovan
drugim enkoderom (druga verzija LZMA SDK), pa bajt-identičnost nije dostižna i nije potrebna.

**Veličine.** Delta u odnosu na original: `min −292 B, medijana +15 B, max +500 B`.
Jače postavke (`nice_len=273`, `BT4`, `depth=200`) daju **veći** izlaz, ne manji —
podrazumevane su bliže originalu.

**Rezerve u bloku nema.** Popuna `0xCC` iza kompresovanih podataka je svega `0–15 B`
(medijana 7) — to je poravnanje, ne slobodan prostor.

**Staje u postojeću veličinu bloka: 93 od 199 (46,7%).**

### 6.12d Šta to znači za izmenu

Blokovi su ulančani preko `Size`, a kontejneri se otvaraju na **apsolutnim offsetima**
(`COrionContainerJob::create(UInt64 iOffset, …)`). Ako blok naraste, sve iza njega se pomera
i apsolutni offseti postaju netačni.

Ali za ciljanu izmenu to je manji problem nego što izgleda:

- menja se **jedan blok**, ostali ostaju bajt-identični (ne diraju se uopšte)
- ako spakovani blok stane u originalnu veličinu → dopuni se `0xCC` → **ništa drugo se ne menja**
- ako ne stane → treba prepakovati sa drugim parametrima dok ne stane, ili prepisati indeks

Pošto već na čistom round-tripu 47% blokova stane, a izmena tipa „skrati ime ulice" smanjuje
sadržaj, izgledi su solidni. Ovo je **inženjerski problem sa jasnim rešenjem**, ne nepoznanica.

> Napomena: `lc/lp/pb` se ne smeju menjati — čitač ih ima fiksirane. Varirati se smeju samo
> parametri pretrage enkodera.

### 6.12b Procena izvodljivosti cilja A

| Prepreka | Status |
|---|---|
| Čitanje formata | **rešeno i potvrđeno na mapi** |
| Interni CRC u `.ATLAS`-u | **ne postoji** |
| `MD5=` u `.conf` | umemo da izračunamo |
| `checkcrc` | nerešen, ali „for testing only" |
| Quick check | opciona; 2 od 3 elementa rešena |
| Ponovno LZMA pakovanje | nije probano |
| Konzistentnost indeksa i klotoida | nije probano |

Preostale nepoznanice su **inženjerske, ne istraživačke**: treba spakovati nazad i složiti
indekse, a ne otkrivati format.

---

## 6.13 Mogući izvor svežih podataka: MIB / NDS (2026)

U `~/Downloads` su dva paketa novije generacije:

| Fajl | Veličina | Šta je |
|---|---|---|
| `P470_N60S5MIBH3_EU.7z` | 15,3 GiB | MIB1 + MIB2 navigaciona baza, mape od **2026-04-01** |
| `AUDI_HIGH_EU_2026-07-01.zip` | 153 MB | PersonalPOI paket (radari i POI), **2026-07-01** |

### Nisu upotrebljivi direktno

| | MMI 3G+ (naš) | Ova dva |
|---|---|---|
| Varijante u `metainfo2` | `9411`, `9307` (četvorocifrene) | `FMU-H-*`, `FM2-*`, `FMQ-*`, `QC2-*` |
| Format | Orion `.ATLAS` | NDS `.psf`, `.tsf`, `.cff` |
| `MetafileChecksum` | 8 heks (CRC32) | 40 heks (SHA-1) |

Arhiv se sam predstavlja kao `"MIB1 navigation database"` i `"MIB2 navigation database"` —
generacija posle 3G+.

### Ali su dobar IZVOR — i to je bitno

Struktura: `Mib1/NavDB/<Zemlja>_eu/0/default/` sa `_Basic.psf`, `_ADAS.psf`,
`_AdvancedRouting.psf`, `_GlobalPOIIndices.psf`, `_Landmark.psf`, plus `Models/*.cff`.
Uz svaki `content.pkg` (JSON) i `hashes.txt` (SHA-1 po fajlu).

**Sadržaj nije šifrovan.** Provereno na `SerbiaMontenegroKosovo_Basic.psf` (47 MB):

```
Beograd     203x        Podgorica   195x
Zemun        32x        Novi Sad     20x
Subotica     12x        Kragujevac    6x
```

Sve u **čistom UTF-8**, bez ključa. Entropija je visoka (prosek 7,81) jer je geometrija
pakovana, ali 27 od 722 bloka je ispod 6,0 — ima strukturiranih regiona, kao i kod `.ATLAS`-a.

`_ADAS.psf` nema imena, što i odgovara — tu su nagibi i zakrivljenost, ne toponimi.

> Napomena: `content.pkg` nosi 128-bajtne vrednosti po fajlu i postoji `content.sig`. To liči
> na RSA-1024 potpis paketa. Potpis štiti **integritet isporuke**, ali sadržaj je čitljiv —
> što je sve što nam treba za korišćenje kao izvora.

### Prvi izvučeni podaci iz NDS-a

Alat: `nds_names.py` (`list` / `stats` / `grep`).

Zapis imena je prost i **nekompresovan**:

```
a1 <UTF-8 ime> 00        stvarno ime
a1 <maska> 00            fonetska maska: slova -> '?', razmaci zadržani
```

Maska služi kao potvrda čitanja — ako joj se dužina poklapa sa imenom, zapis je tačan.
Koristi je glasovni unos destinacije.

**Rezultat na `SerbiaMontenegroKosovo_Basic.psf`:**

| | |
|---|---|
| zapisa imena | 12.569 |
| različitih imena | 2.371 |
| sa fonetskom maskom | 40,2% |
| sa dijakriticima | 865 |

Uzorak — stvarna imena, ispravan UTF-8 sa `č ć ž š đ`:

```
Bulevar kralja Aleksandra   (99x)     Ulica Maksima Gorkog   (89x)
Bulevar oslobođenja         (73x)     Ulica Cara Dušana      (66x)
Ulica Jovana Šerbanovića              R214 (Ulica Karađorđeva)
Veliko Gradište                       Bačka Palanka
M22-1 (Horgoš)                        Donja Šatornja
```

**Ograničenje koje treba znati.** Od 12.569 zapisa, **12.250 je u opsegu 40–44 MB** —
to je onaj nisko-entropijski region. Ostalih 85% fajla je pakovano i daje jedva nešto.

Dakle: tabela imena je zasebna nekompresovana sekcija i **čita se odmah**. Geometrija i
rutirajući graf su i dalje pakovani nepoznatom šemom i traže rad na PSF strukturi.

Uz to, 2.371 različito ime za celu Srbiju, Crnu Goru i Kosovo je premalo za punu mrežu —
verovatno je i tabela imena samo delimično nekompresovana, ili su imena segmentirana.

### Zserio alat — instaliran i proveren

NDS koristi **Zserio** kao jezik šeme. Alat je postavljen u `~/nds_tools/`:

```
~/nds_tools/zserio_compiler/zserio.jar    Core 2.18.2 (Java)
~/nds_tools/venv/                          Python runtime zserio 2.18.2
~/nds_tools/zserio-tutorial-python/        zvanični primer
```

Postavka (Java 21 je već bila na sistemu):

```bash
mkdir -p ~/nds_tools && cd ~/nds_tools
curl -L -O https://github.com/ndsev/zserio/releases/download/v2.18.2/zserio-2.18.2-bin.zip
unzip zserio-2.18.2-bin.zip -d zserio_compiler
python3 -m venv venv && ./venv/bin/pip install zserio
git clone https://github.com/ndsev/zserio-tutorial-python
```

Kompajliranje šeme u Python:

```bash
java -jar ~/nds_tools/zserio_compiler/zserio.jar -python gen -src . sema.zs
PYTHONPATH=gen ~/nds_tools/venv/bin/python skripta.py
```

**Provereno od kraja do kraja** na `tutorial.zs`: kompajliranje daje 6 Python modula,
serijalizacija i čitanje nazad rade (18 B zapis, round-trip ispravan).

### Šta i dalje nedostaje

Prošlo je svih **30 repozitorijuma** organizacije `ndsev`. Svi su Zserio infrastruktura
(kompajler, runtime, tutorijali, servisi) ili NDS.Live alati (`erdblick`, `mapget`,
`ndslive-math`). **Nijedan ne sadrži šemu mape** — nema `.zs` fajlova za putnu mrežu,
geometriju ili ADAS.

Šema je vlasništvo NDS konzorcijuma, dostupna članovima. Bez nje kompajler nema šta da
kompajlira.

Uz to, `.psf` verovatno nije ni goli Zserio: NDS Classic gradivne blokove čuva kao SQLite,
a u našem fajlu **nema `SQLite format 3` potpisa**. Zaglavlje `00 00 3c 00 00 00 f2 00…`
ne odgovara ni SQLite-u ni Zserio streamu. Realno je VW/Harmanov omotač oko NDS sadržaja.

**Zaključak:** alat je spreman i čeka, ali put ka podacima za sada ide preko razbijanja PSF
omotača — isto kako su izvučena imena, bez ikakve šeme.

### PSF omotač — šta je utvrđeno

**Zaglavlje je tabela pokazivača.** Dva su potvrđena:

| Offset u zaglavlju | Vrednost | Šta je |
|---|---|---|
| `+0x035` | `0x02d12841` | **offset potpisa**, poklapa se sa `content.pkg` |
| `+0x04d` | `0x02d12947` | **veličina fajla**, tačno |

Pokazivači stoje na **nepravilnim, ne-4-poravnatim offsetima** — zapis nije poravnat.

**Potpis je potvrđen u bajt.** Na `0x02d12841` stoji 128 bajtova čija se heks vrednost
poklapa sa `checksum.value` iz `content.pkg`. Iza njega je 134 B popune. To je RSA-1024
potpis isporuke.

**Rep nosi tagovane zapise** sa tagom `0xfa`, slično kao `0xa1` u tabeli imena.

### Nema kompresije — i to menja dijagnozu

Pretraženo nad celim fajlom:

| Šema | Potpisa nađeno | Uspešno raspakovano |
|---|---|---|
| zlib (`78 xx`) | 3.107 | **0** |
| LZMA (`5d 00 00`) | 489 | **0** |
| raw deflate | — | **0** |

Uz to, autokorelacija na visoko-entropijskom regionu daje najbolje poklapanje **0,7%**,
a slučajni nivo je 0,39%. **Nema bajtno poravnatih zapisa.**

**Zaključak: podaci nisu kompresovani nego bitovno pakovani.** Zserio pakuje polja na
bitnoj granici bez ijednog bajta viška, pa entropija ide na 7,8 iako ništa nije kompresovano
niti šifrovano. Granice polja ne padaju na bajtove, zbog čega autokorelacija ne vidi ništa.

Imena su bila čitljiva samo zato što se stringovi upisuju kao sirovi UTF-8 bajtovi.

### Šta je onda stvarna prepreka

Ne zaštita — **šema**. Nema šta da se razbija: ni kompresija, ni enkripcija. Ali bez `.zs`
šeme bitovno pakovan zapis se ne može parsirati, jer se granice polja ne mogu otkriti iz
samih podataka.

Dva puta do šeme:

1. **NDS članstvo** — zvanična specifikacija
2. **MIB firmware** — sadrži parser generisan iz šeme; iz njega se struktura može
   rekonstruisati, isto kako je urađeno sa Orionom

### Zašto ovo menja cilj B

Ranije je cilj B značio „sintetiši rutirajući graf, ADAS i TMC iz OSM polilinija".
Sa NDS izvorom to postaje **prevod iz jedne poznate šeme u drugu**: NDS je otvoren
industrijski standard sa objavljenom specifikacijom, i već sadrži isti model podataka koji
Orionov `PSD` traži — graf, ADAS, ograničenja, trake.

Ostaje težak deo (klotoide, konzistentnost indeksa), ali to je prevođenje, ne izmišljanje.

---

## 7. Sadržaj izdanja 6.36.0

`pkgdb/` paketi: `CTY`, `CTY2/3`, `CTYS3TC`, `CTYS3TC2`, `GDB`, `GDB2`, `LABEL`, `LIT`–`LIT4`, `LIT3GP`–`LIT3GP5`, `PIT`, `PSD`, `PSD2`, `PSD3`, `TER`, `TER2`, `XAC`, `XAC2`, `XAC3`.

Najmanji `.ATLAS` fajlovi, dobri za rad:

```
pkgdb/TER2/72_Europe.4_2.1.ATLAS                214 MB   <- radni uzorak
pkgdb/CTYS3TC2/3PN221EU22083P1666a.4_4.1.ATLAS  562 MB
pkgdb/PSD3/APN221EU22093P1664a.5_1.2.ATLAS      843 MB
pkgdb/PSD/APN221EU22093P1664a.5_1.0.ATLAS      2097 MB
```

Meta fajlovi u rootu: `build1` (verzija i build), `config.nfm` (`pkgpath=./pkgdb`), `DBInfo.txt` (PartNumber), `metainfo2.txt` (`MetafileChecksum`, spisak varijanti i paketa). Po paketu ide `<IME>.conf` sa `size=`, `MD5=` i `checkcrc=` za pripadajući fajl — besplatna provera integriteta pre parsiranja.

---

## 8. Otvoreno

- [x] ~~`decode` na listovima ne prikazuje imena kolona~~ — rešeno 2026-08-31. Uzrok nije bio nasleđivanje šeme nego dve stvari: parser je tražio `0x00` iza tipa, a listovi koriste `0x01`; i imena se moraju poravnati na tipove (1:1 u korenu, 1:2 u listu), ne zipovati. Nasleđivanje iz ranijeg bloka ostaje kao rezerva u `resolve_cols`.
- [ ] Utvrditi šta je `*.ptr` u listu. **Suženo 2026-08-31:** nije broj sektora — `13107360 × 2048 = 26,8 GB` preliva fajl od 214 MB za 125×. Kao bajt-offset staje (6,1% fajla), ali **nije poravnat na 2048** (`ptr/2048 = 6400,078`) i na toj poziciji ne stoji početak bloka nego spakovani podaci. Sledeća hipoteza: vrednost je u jedinicama `ContainerSize` (8192) — `13107200 = 8192 × 1600`, ostatak 160 — ili je polje bit-pakovano.
- [ ] **Pročitati `calculateOffsets` (`FUN_0832ead8`)** — jedina preostala karika. Raspored kolona nije sekvencijalan (12.418 B neobjašnjene razlike), pa se položaj svake kolone mora izvesti iz te funkcije. Empirijsko pogađanje je iscrpljeno.
- [x] ~~Implementirati bitovni čitač za tip 3~~ — urađeno, `atlas_bits.py`, verifikovan na 4 širine.
- [x] ~~Povezati deskriptor sa blokovima podataka~~ — podaci su u raspakovanom sadržaju drugih blokova; kolone nađene, vidi 6.10i.
- [x] ~~Implementirati raspored po pravilu iz 6.10l~~ — potvrđeno na tri bloka, vidi 6.10m.
- [x] ~~Računati bazu podataka po bloku~~ — urađeno traženjem po bloku, 1701 čistih parova, vidi 6.10n.
- [x] ~~Odrediti tačnu vrednost pomaka~~ — izmereno ≈78,25, potvrđeno na Minsku.
- [ ] Popraviti čitanje kolone visina (sada se `u32` čita kao `u16`, otud naizmenične nule).
- [ ] Stara stavka: tačna vrednost pomaka (≈80° potvrđeno, precizno ne) — iz koda ili poznate deonice.
- [ ] Stara stavka: računati bazu (kraj šeme + zastavice), pa ponoviti uzorkovanje kolone `0` na čistim podacima.
- [ ] Stara stavka: raspored po pravilu: `offset += ceil(bitovi/8)`, uz širinu izvedenu iz maske. Time se kolone vezuju za imena iz kataloga po redosledu.
- [ ] Identifikovati drugu kolonu u trojci — merenje na celom `PSD3` isključuje „dužina + konstanta" (granice traže 91,9 i 101,2). Vezati kolone za imena iz kataloga umesto pogađati po opsegu.
- [ ] ~~Utvrditi pomak kolone dužine.~~ **Suženo:** mora biti **umnožak `2^18`** (inače se ruši poravnanje mreže), čime je tačno `80°` isključeno. Kandidati oko `3051`–`3052 × 2^18`. Odrediti iz koda ili iz poznate tačke.
- [ ] Stara stavka: iz `(offset, size)` parova u katalogu naći blok koji nosi kolonu, pa tek onda čitati vrednosti.
- [ ] Stari zadatak, i dalje otvoren: implementirati bitovni čitač za tip 3: pročitati 5-bitnu širinu (+1), pa vrednosti na toj širini; proveriti na koloni koordinata `PSD`-a. Ostaje utvrditi da li je nad tim još i delta kodiranje.
- [ ] Mapirati kodove 1/2/3 na klase `CByteBit` / `CBitPlain` / `CBitBit`.
- [x] ~~Utvrditi kodiranje vrednosti u koloni koordinata. **Suženo 2026-08-31:** postoje četiri režima (`CByte/CBit` × `Plain/Bit`), offseti su u **bitovima**, vrednosti mogu biti bitovno pakovane na širinu iz `STypeTrait<EType>::Width`. Treba pročitati `CDecompression::create` da se vidi koji kod bira koji režim, pa implementirati bitovni čitač.~~ — mehanizam nađen, vidi 6.10f.
- [x] ~~Dekodirati `PSD`~~ — kontejner, kompresija i rečnik kolona rešeni 2026-08-31. Ostaje dekodiranje samih redova (tipovi i skale u `PSD` 5.1.1).
- [ ] Nabaviti drugo izdanje radi `diff`-a. Radi bilo koji par verzija istog paketa, ne mora baš 6.34.1.
- [ ] Potvrditi da li su offseti u listovima u sektorima (2048) — sektorska logika je dokazana u CDM sloju, ali ne još u samom `.ATLAS`-u.
- [ ] Kako se računa 64-bitni ključ za dedup `.ATLAS` unosa.

---

## 9. Hronologija

**2026-08-31**

- Nađen i raspakovan firmware; napisan `ifs_tool.py` sa sopstvenim LZO1X dekompresorom
- Lociran `NavCore` kao parser; tabela ekstenzija i `.ATLAS` grana
- Instalirana Ghidra 12.1.3, headless analiza; potvrđen sektor 2048 i 24-bitno adresno polje → 32 GiB plafon
- Preuzeto izdanje 6.36.0; MD5 TER2 potvrđen
- Entropija: nije enkriptovano
- Dekodiran heder, blok-struktura, tipovi, koordinate (×10⁷) i geometrija TER-a
- **Raspakivanje rešeno**: LZMA1 raw (lc=3 lp=0 pb=2, dict 64K); PSD3 3011/3012 delova OK
- **Šema rutirajućeg grafa pročitana**: Longitude/Latitude/PointLlh/Lane/ManoeuvrePart…
- Lanac blokova preko `Size` prošetan kroz svih 5 testiranih paketa, pokriva fajlove tačno
- `uncompress` pročitan: tip kompresije, do 8 delova, zlib/LZMA
- `COrionDatabase::create` = `FUN_08322504`; heder potvrđen polje po polje; tri verzije formata (4.2.1 / 4.4.1 / 5.1.1)
- Nađen Orion klaster u `NavCore`: pun C++ API, imena struktura, potvrde hedera, zlib/LZMA
- `decode` poravnava imena na tipove (režimi 1:1 i 1:2); listovi mreže sada čitljivi sa imenima

---

## 6.14 Alat za MIB2 firmware: dump_hbcifs

Za sledeći korak (kad se nabavi MIB2 firmware) kompajliran je i spreman
**`dump_hbcifs`** — https://github.com/ReverseEngDotDev/dump_hbcifs

Binarij: `~/mmi3g-atlas/dump_hbcifs`. Rukuje sa tri formata u jednom firmware fajlu:
QNX IFS, ImageFS i **HBCIFS (Harman Becker Compressed IFS)** — baš format MIB2 root particije.
Prolazi kroz sve sekcije (pre-boot / boot / root) i vadi fajlove.

`HBCIFS` zaglavlje (iz `hbcifs.h`): magic `"hbcifs"`, pa `decompressed_size`,
`compressed_size`, dva CRC16, i bajt kompresije — **0x01=LZO, 0x03=UCL, 0x04=zlib(?)**.

Gradnja (zavisnosti: `lzo` i `openssl@3` iz brew-a; UCL sagrađen iz izvora jer je Homebrew
`ucl` pogrešna biblioteka):

```bash
# UCL iz izvora (autotools iz 2004 ne poznaje arm64, pa direktno):
cd /tmp && curl -sL oberhumer.com/opensource/ucl/download/ucl-1.03.tar.gz | tar xz
cd ucl-1.03 && for c in src/*.c; do gcc -O2 -fPIC -Iinclude -I. -w -c "$c" -o "${c%.c}.o"; done
ar rcs /tmp/ucl-install/libucl.a src/*.o && cp -r include/ucl /tmp/ucl-install/include/

# dump_hbcifs:
cd /tmp/dump_hbcifs && g++ -std=c++11 -O2 -w -o dump_hbcifs main.cpp dump_hbcifs.cpp \
  -I. -I$(brew --prefix lzo)/include -I/tmp/ucl-install/include -I$(brew --prefix openssl@3)/include \
  -L$(brew --prefix lzo)/lib -L$(brew --prefix openssl@3)/lib \
  /tmp/ucl-install/libucl.a -llzo2 -lz -lcrypto
```

Napomena: na našem 3G+ `ifs-root.ifs` ne radi — očekivano, jer taj fajl ima Harmanov
potpis `0x00ff7eeb`, a alat traži standardni QNX `0x00fa7eeb`. Za 3G+ ostaje naš
`ifs_tool.py`; `dump_hbcifs` je za MIB2 generaciju. **Nije još testiran na stvarnom MIB2
firmveru — čeka fajl.**

---

## 6.15 PROBOJ: MIB2 firmware nabavljen i parser lociran

`MHI2_ER_AU57x_K3663_1_MU1425_AIO.7z` (5,8 GiB, solid) — kompletan SWDL dump za MIB2 High,
Audi, evropski, train K3663. Raspakovane ključne particije u `/tmp/mib_fw/`:

| Particija | Format | Sadrži |
|---|---|---|
| `MMX2/app/70/default/app.img` | **QNX6 fs** (1 GB) | **navigacioni parser** |
| `RCC/ifs-root/21/default/ifs-root.ifs` | QNX IFS | RCC sistem |
| `MMX2/mifs-stage2/…/mifs-stage2.img` | LZOZ | boot stage |
| `MMX2/eifs/…/eifs.img` | ELF-fs | early ifs |

**`app.img` sadrži parser** — 51 pojava `psf`. Kao i kod Oriona, C++ imena su ostala:

- `GeoEdgeIdGeocoderPSF` — geokoder koji čita PSF, sa imenovanim radnim koracima
  (`Workstep1_InitStreetReading`, `Workstep2_InitClusterLoading`, `Workstep5_InitAdminInfoReading`)
- `PSFInfo::Init`, `PSLPSFCache` — učitavanje i keš PSF-a
- `sd.PSF_Detailed_Version` provera (isto polje kao u `content.pkg`)
- `WorldCartographicLayer_Basic.psf` — ime sloja
- **`asi::navigation::rdvtypes::LandSegment`** i cela `asi::navigation::*` hijerarhija:
  `MapDataProvider`, `RouteDataProvider`, `PositionDataProvider`, `NavIconProvider`, `styledb`
- biblioteke: `libpnav.so`, `libPNavATF.so`, `libLuaMap.so`

Skelet imena sačuvan: `~/mmi3g-atlas/mib2/nav_strings.txt` (1600 linija).

### Prepreka: QNX6 filesystem, fragmentiran

`app.img` je QNX6 Power-Safe (`eb 10 90` boot + x86). macOS ga ne montira, a fajlovi su
fragmentirani — prosto ELF-carving ne radi (string geokodera je 23 MB od najbližeg ELF
headera). Za čist `.so` treba **qnx6 reader** (Linux `mount -t qnx6`, ili namenski alat).

### Gde smo — pošteno

Sad **prvi put postoje oba kraja lanca**:
- **izvor:** NDS/PSF podaci iz 2026 (raspakovani, imena čitljiva) — `nds_names.py`
- **parser:** MIB2 nav binariji koji te podatke čitaju — u `app.img`, imena klasa vidljiva

Ali cilj koji korisnik želi (izvući nove mape i **prepakovati u Orion `.ATLAS` za 3G+**) je
**cilj C** iz naše skale: traži (1) pun reverse PSF/NDS šeme iz `libpnav.so` kroz Ghidru,
(2) čitanje geometrije i grafa, (3) generisanje kompletne Orion baze sa klotoidama i
konzistentnim indeksima. To je višenedeljni RE posao, ne jedan korak.

**Sledeći konkretan korak:** izvući `libpnav.so` iz qnx6 filesystema (treba Linux ili
qnx6 alat), pa ga u Ghidru — isto kako je urađeno sa `NavCore`. Odatle se čita PSF format.
