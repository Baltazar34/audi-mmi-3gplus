# Audi MMI 3G Plus — format mapa i konverter MIB → 3G+

Automobili sa Audi **MMI 3G Plus** navigacijom (A6/A7/A8/Q3 generacije C7,
firmware grana HN+R) dobili su poslednje zvanične mape 2023. godine. Novije
Audi/VW jedinice na **MIB** platformi i dalje dobijaju mape svake godine.

Ovaj repozitorijum dokumentuje oba formata mapa, rekonstruisana isključivo
čitanjem firmvera koji ih koristi, i sadrži kompletan, proveren lanac alata
koji od MIB mape pravi strukturno ispravnu MMI 3G Plus `.ATLAS` bazu za
rutiranje. Sve je rađeno na Macu, nad kopijama fajlova. Auto nije diran.

Engleska verzija ove strane je [README.md](README.md). Detaljna
dokumentacija u `docs/` je uglavnom na srpskom; ulazne strane i indeks alata
su na engleskom.

## Šta radi, a šta ne

| Korak | Stanje |
|---|---|
| Raspakivanje 3G Plus firmvera (QNX IFS, sopstveni LZO1X dekompresor) i lociranje parsera mapa | urađeno |
| Raspakivanje MIB (MHI2) firmvera (QNX6 image) i lociranje PSF parsera | urađeno |
| Orion `.ATLAS` format: heder, lanac blokova, LZMA1 raw, šema kolona, bitovni kodeci, prostorni ključ bloka, INDEX stablo | urađeno, dokazano bajt-po-bajt |
| Čitanje novije MIB `PSF60` mape: klasteri, topologija, geometrija, imena, jezici, atributi puta, AdvancedRouting/ADAS okvir | urađeno nad celim Srbija/Crna Gora/Kosovo skupom |
| Pisanje Orion objekata (PointLlh, Node/Edge, klotoidne ose, svojstva) | urađeno, sa samoproverom |
| Pisanje celog `.ATLAS` fajla (HEADER / REVISION / INDEX / CONTAINER) i njegovog `.conf` | urađeno; writer sastavlja originalnu PSD bazu od 5 GB bajt-identično |
| Puna konverzija jedne MIB regije u 3G Plus bazu za rutiranje | urađeno: `SRB.5_1.0.ATLAS`, 32,3 MB, prolazi sve verifikatore |
| Ostali pkgdb slojevi (3D gradovi, teren, tekst, TMC, POI) | formati dekodirani, writeri po sloju nisu napravljeni |
| Semantika unutrašnjosti AdvancedRouting / ADAS zapisa, VidTable i XAC tekst imena | delimično otvoreno, vidi status |
| Instalacija generisanog paketa u auto | **nije moguća bez potpisa izdavača**, vidi dole |

Brojke za pun prolaz Srbije:

| Stavka | Vrednost |
|---|---|
| MIB ivice / čvorovi | 838.433 / 717.730 |
| Prostorne ćelije / CONTAINER blokovi | 3.877 / 3.915 |
| Generisani `.ATLAS` | 32,3 MB, jedan deo, dva INDEX lista |
| Round-trip originalnog PSD-a (3 dela, 5,04 GB) | 254.828 blokova, 0 odstupanja |
| Unit testovi | 146, svi prolaze |

## Gde staje, i zašto

3G Plus jedinica proverava paket mapa samo pri instalaciji, u toku
software-download procedure. Provera je lanac: potpis paketa (`.pkg.sig`,
proverava ga proces `cryptomanager` javnim ključem na uređaju), CRC svakog
`.conf`-a, MD5 svakog `.ATLAS`-a i FSC licenca vezana za part number mape.
Nova mapa znači nov MD5, nov CRC `.conf`-a i paket koji može da potpiše
samo izdavač.

Projekat reprodukuje svaku kariku tog lanca koja se može reprodukovati
(MD5, quick-check MD5, raspored `.conf`-a) i dokumentuje ostatak onako
kako stoji u firmveru. **Ne** patchuje firmware, ne falsifikuje potpise,
ne koristi fabričke „skip" prekidače i ne nudi zaobilaženje FSC-a. Pročitaj
[docs/FW_PROTECTION_MODEL.md](docs/FW_PROTECTION_MODEL.md) pre nego što pitaš.

## Čega nema u repozitorijumu

- Nema mapa. Ni originalnog 3G Plus izdanja, ni MIB skupa, ni generisanog
  `.ATLAS`-a. Sve je licencirani sadržaj; `.gitignore` odbija te ekstenzije.
- Nema firmware image-a ni izvučenih binarnih fajlova. Dokumenti navode
  adrese, stringove i dekompajliranu logiku; za ponavljanje dokaza kroz
  `run_*_re.py` treba sopstvena kopija firmvera.
- Nema kredencijala ni linkova ka tuđim dump-ovima.

## Brzi početak

Potreban je Python 3.10 ili noviji, samo standardna biblioteka. Opciono:
`7z` (čitanje arhiva direktno) i Ghidra 11+ (ponavljanje firmware dokaza).

```bash
git clone <ovaj repo> audi-mmi && cd audi-mmi
python3 -m unittest discover -s tests
```

Alati se usmeravaju na tvoje ulaze promenljivima okruženja. Pun spisak i
identiteti fajlova (imena, veličine, SHA-256) su u
[docs/INPUT_INVENTORY.md](docs/INPUT_INVENTORY.md).

```bash
export MIB_MAP_ROOT=/putanja/do/Mib1/NavDB/SerbiaMontenegroKosovo_eu/0/default
export MMI3G_PKGDB=/putanja/do/8R0051884KL_6.36.0_2023/pkgdb
export NAVCORE_ELF=/putanja/do/extracted/usr/apps/NavCore
```

Prvo što vredi probati:

```bash
# MIB strana: šta je u PSF fajlu
python3 tools/psf_decode.py inspect "$MIB_MAP_ROOT/SerbiaMontenegroKosovo_Basic.psf"

# 3G Plus strana: šeme u originalnom Orion sloju
python3 tools/orion_layer_survey.py "$MMI3G_PKGDB/PSD3/APN221EU22093P1664a.5_1.2.ATLAS" --limit 5

# Ceo lanac provere kontejnera nad originalnim PSD-om
python3 tools/run_container_pipeline.py tools/orion_container_pipeline.json \
  --state out/orion_container_pipeline_state.json --jobs 3
```

Konverzija od početka do kraja, korak po korak sa komandama, je u
[docs/PIPELINE.md](docs/PIPELINE.md).

## Mapa repozitorijuma

```
README.md               engleska strana         README.sr.md      ova strana
docs/                   dokumentacija, redosled čitanja u docs/README.md
tools/                  95 samostalnih Python alata, jedan posao po alatu, svi imaju --help
tests/                  unit testovi (integracioni se preskaču bez lokalnih podataka)
ghidra_scripts/         generičke headless Ghidra skripte za tools/run_*_re.py
legacy/mmi3g-atlas/     prvi prolaz kroz Orion/ATLAS (avgust 2026) i njegov dnevnik
scripts/                održavanje repozitorijuma (generator indeksa alata)
out/                    generisani izveštaji i buildovi, van gita
```

Svaki analitički alat je skripta koja prođe ceo korpus, ispisuje napredak,
staje na prvoj neusaglašenosti, piše JSON izveštaj i `CHECKSUMS.sha256`.
Tvrdnje u dokumentima upućuju na te izveštaje.

## Dokumentacija

Počni od [docs/README.md](docs/README.md). Ukratko:

1. [PROJECT_HISTORY.md](docs/PROJECT_HISTORY.md) — kako je išlo, dan po dan (EN)
2. [legacy/mmi3g-atlas/DOCS.md](legacy/mmi3g-atlas/DOCS.md) — 3G Plus firmware i Orion format od nule (SR)
3. [ATLAS_CONTAINER.md](docs/ATLAS_CONTAINER.md) — dokazana specifikacija `.ATLAS` kontejnera (SR)
4. [PKGDB_LAYERS.md](docs/PKGDB_LAYERS.md) — svaki sloj 3G Plus paketa mapa (SR)
5. [PSF60_FORMAT.md](docs/PSF60_FORMAT.md) — MIB format mapa (SR)
6. [PSF60_DECODER_GUIDE.md](docs/PSF60_DECODER_GUIDE.md) — vodič kroz alate (SR)
7. [ORION_ADAPTER.md](docs/ORION_ADAPTER.md) — MIB izvor u Orion rečnik (SR)
8. [PIPELINE.md](docs/PIPELINE.md) — konverzija od početka do kraja (EN)
9. [FW_PROTECTION_MODEL.md](docs/FW_PROTECTION_MODEL.md) — potpis, CRC, FSC (SR)
10. [IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) — zatvorene i otvorene stavke (SR)
11. [TOOLS.md](docs/TOOLS.md) — indeks svih alata (EN)

## Pravna strana

Reverse engineering formata radi interoperabilnosti je u EU dozvoljen
(Direktiva 2009/24/EZ, čl. 6). Granica koje se projekat drži je
redistribucija sadržaja mapa i zaobilaženje zaštite uređaja; ni jedno ni
drugo se ovde ne radi. Kod je pod MIT licencom, vidi [LICENSE](LICENSE).
Audi, MMI, MIB i HERE su zaštitni znaci svojih vlasnika; projekat nije
povezan ni sa jednim od njih.

## Pozadina

Projekat je počeo zato što je jedan auto imao mapu iz 2023. i nikakav način
da dobije noviju. Priča je u [docs/PROJECT_HISTORY.md](docs/PROJECT_HISTORY.md).
Ako voziš istu jedinicu i hoćeš da nastaviš odavde, otvori issue.
