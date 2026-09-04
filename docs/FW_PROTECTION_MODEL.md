# Model zaštite NavDB — faktičko stanje (read-only RE)

Poslednje ažuriranje: 2026-09-03. Dokument opisuje kako firmver proverava
navigacionu bazu. Sve tvrdnje su iz stringova i tabela u
`$MMI3G_NAV_ELF`
(SH4 ELF, image base `0x08040000`). Alat: `tools/fw_protection_model.py`.

## Gde zaštita živi

Sve provere su u jednoj klasi: **`CPNavDBChecker`** (`CPNavDBChecker.cpp`).
Ona radi u **SWDL toku** (software download / instalacija / aktivacija baze),
a ne pri svakom čitanju mape. Ulazi u nju su eksplicitni:

- `CPNavDBChecker::startCheck`
- `CPNavDBChecker::startAutomaticCheckAndInstall`
- `CPNavDBChecker::start Activation`
- `CPNavDBChecker::startAutomaticCheckAndInstall`

Runtime strana je odvojena: baza se samo **montira** (`isMounted`,
`lvmMount lvm path %s already mounted`, `mount:%s@%s`, `Nav_PreloadDatabase`).
U toj open/mount putanji nema nijednog stringa potpisa/CRC/FSC — dakle nema
dokaza o proveri potpisa po čitanju. Provera se radi **jednom, pri
instalaciji/aktivaciji**, rezultat se pamti u SIS-u
(`waitForActivation installation complete, save packet in sis`), pa se posle
baza samo koristi.

## State-mašina provere

`FUN_083179f0` mapira stanja (tabela imena na `0x08317a48`):

    eIdle → eStart → eCheckSignature → eCheckCrc →
    eAnalyseCheckedPackages → eWaitForActivation →
    eFinishFinalize → eWaitingForIdle

Redosled provera i njihovi error-bitovi (`CPNavDBChecker::displayErrorBits`):

| Bit | Provera | Metod u klasi |
|---|---|---|
| `VERSIONCHECK_FAILED` | verzija baze vs zahtevana | `checkVersions`, `isVersionCompatible` |
| `REGIONCHECK_FAILED` | region baze vs uređaj | `checkVersions [%d] ... region %s != %s` |
| `VARIANTCHECK_FAILED` | varijanta (model/tip jedinice) | `checkVersions ... model %d does not match` |
| `SIGNATURE_FAILED` | kriptografski potpis paketa | `checkSignature`, `requestCheckSignature` |
| `CRCCHECKFAILED` | CRC baze | `checkCrc`, `quickCrcCheck` |
| `FSC_FAILED` | FSC licenca za paket | `checkFsc` |
| `PACKET_CHAIN_INCOMPLETE` | lanac paketa nepotpun | `mergeChainedPackagesErrorBits` |
| `ISUPGRADE` / `ISDOWNGRADE` | smer verzije | `isDownOrUpgrade` |
| `NO_NAV_MEDIUM` | nema medija | — |
| `SIS_REQUEST_FAILED` | SIS servis | `reportSisStatus` |

## Potpis — ko ga proverava

`checkSignature` čita potpis iz fajla
(`checkSignature read signature data from %s`,
`workerThreadFunctionGetSignatureFile signature file opened: %s`) i **prosleđuje
ga Crypto servisu**, ne proverava sam:

    OBSOLETE SPHSwdlSelection::requestCheckSignature!!! Move to Crypto!
    project_devctrl_cryptomanager_CCMFscCheckJobPolicy

Dakle stvarna kriptografija je u zasebnom `cryptomanager` procesu. Potpis paketa
je asimetričan (privatni ključ je kod izdavača mape); firmver ima samo javnu
proveru. To znači da nova baza koja ide kroz normalan SWDL mora imati validan
potpis izdavača; potpis se proverava javnim ključem, a izračunava se privatnim
ključem koji je kod izdavača.

## FSC — licenca vezana za paket

`checkFsc` traži sistemski FSC u opsegu za dati paket
(`checkFsc packet fsc = 0x%x, range to search: 0x%x - 0x%x`,
`checkFsc no valid fsc found for package %s`). Ako paket nema FSC info, provera
prolazi (`no FSC in packet info included ==> check ok`). FSC je vezan za
PartNumber baze (potvrđeno i ranije: originalni `PartNumber` se čuva zato što je
aktivacija vezana za njega). Legalni/ilegalni FSC-ovi se prate
(`legalFscCollector`, `illegalFscCollector`, `/HBpersistence/FSC/illegal/signature`).

## „Skip" prekidači — ko ih pali i zašto

Ovo je bio glavni cilj: ko triggeruje obilazak i zašto. Nalaz:

Prekidači **nisu** opšti bypass. To su konfig-ključevi koji se čitaju iz
persistence fajlova pod `/HBpersistence/SWDL/`, i vezani su za specifične
hardverske/inženjerske slučajeve:

| Ključ / fajl | Namena (iz konteksta u binaru) |
|---|---|
| `skipCheckSignatureAndVariant` | uz `checkBentleyRsuNaviDbWorkaround => Ignore missing variant` — **workaround za Bentley RSU** (Rear Seat Unit) gde varijanta nedostaje |
| `skipCheckRegion` / `/HBpersistence/SWDL/region.txt.z` | preskakanje region provere |
| `info/IgnoreRegionVariant.txt`, `requestIgnoreRegionVariant` | ignorisanje region/varijante |
| `/HBpersistence/SWDL/SimulateBentley.txt`, `SimulateBentleyRsu.txt` | simulacija Bentley/ RSU okruženja |
| `/HBpersistence/SWDL/SwdlProductionMode.txt` | **production mode** — `decodeProgress: error received, ignored in production mode`, `automaticActivate ... errors=0x%x are ignored` |
| `IgnoreKeyboard`, `IgnoreMainU`, razni `Ignore*` | proizvodni/servisni toggeri |

Zaključak o triggeru: preskakanje provera pale **fabrički/servisni/RSU
workaround flagovi** iz `/HBpersistence/` — namenjeni proizvodnji i posebnim
jedinicama (Bentley Rear Seat Unit), a `production mode` dodatno „proguta" deo
grešaka. To su servisni/proizvodni mehanizmi, ne korisnički.

## Šta ovo znači za cilj (mapa u autu) — faktički

1. Potpis/CRC/FSC/region/varijanta se proveravaju **pri instalaciji/aktivaciji**
   paketa kroz `CPNavDBChecker`, ne pri čitanju mape.
2. Posle uspešne aktivacije baza se samo montira (LVM) i čita; nema dokaza o
   ponovnoj proveri potpisa po čitanju.
3. Validan potpis paketa zahteva privatni ključ izdavača.
4. „Skip" flagovi su vezani za fabričke/RSU/production slučajeve.

## Obim analize

Tačna kripto-provera unutar `cryptomanager` procesa (zaseban binar) nije
dekompajlirana; taj server binar nije u ovom delimičnom IFS extract-u. Ponašanje
na samom uređaju nije verifikovano. Sve gore je izvedeno iz statičkih stringova
i tabela `MMI3GNavigation`; opis je model formata provere, ne izvršni trag na
uređaju.

## cryptomanager — arhitektura provere (faktički model)

`cryptomanager` je zaseban **devctrl** proces (`CCryptoManagerComp` /
`CCryptoManagerImpl`, `project_devctrl_cryptomanager_*`). Sam server binar nije
u ovom delimičnom IFS extract-u; sve dole je iz **klijentskog interfejsa** koji
nose MMI3G aplikacije (stubovi/proxy/eventi). Opis je model, ne izvršni dokaz.

### Servisi (SPH interfejsi)

- `SPHCryptoManager` — glavni servis (`requestCheckSignature`,
  `responseSignatureChecks`, `requestCheckFscs`).
- `SPHCryptoManagerHMI` — korisnički (`RQST_importFSCs`, `ATST_fscList`,
  `RQST_fscDetails`, `RPST_fscDetails`) — unos/pregled FSC-ova.
- `SPHCryptoManagerDiagnosis` — dijagnostika (engineering pristup FSC-ovima).

Klijenti (npr. `CPNavDBChecker`) šalju zahtev preko NDR/IPC-a i dobijaju
`responseCheckSignature %d %s`; ne rade kripto sami.

### Potpis — algoritam i tok

- Primitiva je **RSA**: `EscRsa_DecryptSignature failed %d`. Provera
  dekriptuje potpis javnim ključem i poredi sa izračunatim digest-om:
  `Calculated signature size %d, given length %d`,
  `Signature is wrong for %s`, `Check signature returns: %d`.
- Koraci (iz `NDigitalRights` / `TDigitalRightsSignatureCheckJob`):
  `extractSignature` → `checkSignature` → RSA decrypt → poređenje.
  `doesn't contain valid signature header` = format potpisa se prvo validira.
- Meri se i vreme: `Signature check in %lld msec`.

### Ključevi (na uređaju je samo javni)

- Javni ključ: `/mnt/efs-persist/Keys/FSCKey/FSC_public_signiert.bin` — i sam
  je potpisan („signiert"). Privatnog ključa nema u firmveru — to je i razlog
  zašto se validan potpis ne može proizvesti na uređaju.

### FSC (Feature enable code / licenca)

- Format: magični header `0x8080` (`FSC Format wrong ... != (0x8080)`), polja
  size/content/signature/format; FSC ID je 32-bitni (`%.8x`).
- Sadrži **VIN** (`isVINinFSC and mHasVin`) — vezan za vozilo.
- Provere: `checkFSCFormat`, `checkFSCSize`, `isVINinFSC` (`CCMFSCFacade`).
- Legalni/ilegalni se prate i loguju:
  `/HBpersistence/FSC/illegal/{size,content,signature,format}`,
  `collectIllegalFSCInfo`, `/HBpersistence/FSC/Logs/Security_Exceptions.log`.
- Izvori FSC-a: `/mnt/efs-extended/FSC.txt`, `/HBpersistence/FSC/cache`.

### Exception liste (potpisane)

- `Fazit Exception List` i `AudiFSC Exception List` — potpisane liste izuzetaka
  (`Signature calculation failed for AudiFSC Exception List`), preko
  `TDigitalRightsExceptionListCheckJob` / `CCMExceptionListCheckJobPolicy`.

### Zaključak modela

Lanac je: paket → `TDigitalRightsSignatureCheckJob` (RSA nad digest-om,
javni ključ) → FSC provera (format/size/VIN, `0x8080`) → rezultat nazad
klijentu. Cela snaga je u tome što je **privatni ključ van uređaja**; javna
strana može samo da potvrdi ili odbaci potpis.
