#!/usr/bin/env python3
"""orion_atlas_header_decode.py — dokazana specifikacija ATLAS `HEADER` bloka.

Polja nisu pogodjena nego izvedena poredjenjem svih ATLAS fajlova jednog
pkgdb izdanja.  Jedno izdanje sadrzi vise nezavisnih baza (PSD, CTY,
CTYS3TC, TER), a svaka je podeljena na 2-3 medijska dela.  Zato se svako
polje proverava kao invariant preko cele grupe:

    +0x00  u8 len + ime bloka, popuna 0xcc do 0x10
    +0x10  u32   velicina bloka = 4096
    +0x14  u8[4] format verzija {major, minor, rev, 0}
    +0x18  u16   konstanta 0x016c
    +0x1a  u8    ukupan broj delova baze
    +0x1b  u8    indeks ovog dela
    +0x1c  u32   identifikator baze
    +0x20  u8 len + ime engine-a ("Orion"), polje od 8 B
    +0x28  u32   100
    +0x2c  u32   0
    +0x30  u8 len + ime kontejnera ("Atlas"), polje od 8 B
    +0x3c  u16 + u16 jos neimenovana para
    +0x40  u64   build identifikator, isti za sve delove jedne baze
    +0x48  u64   ukupna velicina svih delova baze
    +0x50  u64   velicina ovog dela = velicina fajla
    +0x58  u64   zbir velicina svih prethodnih delova
    +0x60  popuna 0xcc do kraja bloka

Provere koje moraju proci za svaku bazu:

  * `part_index` je tacno 0..part_count-1 i svaki se javlja jednom;
  * `part_size` je jednako stvarnoj velicini fajla;
  * `preceding_size` je zbir `part_size` svih delova sa manjim indeksom;
  * `format_version` i `build_id` su isti u svim delovima jedne baze.

Skripta ne menja ulazne fajlove.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path

HEADER_BLOCK_SIZE = 4096
PAD_BYTE = 0xCC
PART_STRUCT_CONSTANT = 0x016C


def read_counted_string(data: bytes, offset: int, field: int) -> tuple[str, bytes]:
    length = data[offset]
    text = data[offset + 1:offset + 1 + length].decode("ascii")
    spill = data[offset + 1 + length:offset + field]
    return text, spill


def decode_header(path: Path) -> dict[str, object]:
    with path.open("rb") as source:
        block = source.read(0x60)
    name_length = block[0]
    name = block[1:1 + name_length].decode("ascii")
    engine, engine_spill = read_counted_string(block, 0x20, 8)
    container, container_spill = read_counted_string(block, 0x30, 12)
    return {
        "file": str(path),
        "file_size": path.stat().st_size,
        "block_name": name,
        "name_padding_ok": set(block[1 + name_length:0x10]) <= {PAD_BYTE},
        "block_size": struct.unpack_from("<I", block, 0x10)[0],
        "format_version": list(block[0x14:0x18]),
        "part_struct_constant": struct.unpack_from("<H", block, 0x18)[0],
        "part_count": block[0x1A],
        "part_index": block[0x1B],
        "database_id": struct.unpack_from("<I", block, 0x1C)[0],
        "engine": engine,
        "engine_spill": engine_spill.hex(),
        "word_0x28": struct.unpack_from("<I", block, 0x28)[0],
        "word_0x2c": struct.unpack_from("<I", block, 0x2C)[0],
        "container": container,
        "container_spill": container_spill.hex(),
        "word_0x3c": struct.unpack_from("<H", block, 0x3C)[0],
        "word_0x3e": struct.unpack_from("<H", block, 0x3E)[0],
        "build_id": struct.unpack_from("<Q", block, 0x40)[0],
        "total_size": struct.unpack_from("<Q", block, 0x48)[0],
        "part_size": struct.unpack_from("<Q", block, 0x50)[0],
        "preceding_size": struct.unpack_from("<Q", block, 0x58)[0],
    }


def database_key(path: Path) -> str:
    """Sve delove jedne baze veze zajednicko ime bez indeksa dela."""
    return re.sub(r"\.(\d+)$", "", path.stem)


def verify(headers: list[dict[str, object]]) -> dict[str, object]:
    groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    for header in headers:
        groups[database_key(Path(header["file"]))].append(header)

    results = []
    failures = []
    for key, members in sorted(groups.items()):
        members.sort(key=lambda item: item["part_index"])
        indices = [item["part_index"] for item in members]
        counts = {item["part_count"] for item in members}
        versions = {tuple(item["format_version"]) for item in members}
        builds = {item["build_id"] for item in members}
        totals = {item["total_size"] for item in members}

        checks: dict[str, object] = {
            "part_indices_complete": indices == list(range(len(members))),
            "part_count_agrees": counts == {len(members)},
            "format_version_uniform": len(versions) == 1,
            "build_id_uniform": len(builds) == 1,
            "total_size_uniform": len(totals) == 1,
            "block_size_is_4096": all(
                item["block_size"] == HEADER_BLOCK_SIZE for item in members),
            "engine_is_orion": all(item["engine"] == "Orion" for item in members),
            "container_is_atlas": all(item["container"] == "Atlas" for item in members),
            "part_struct_constant": all(
                item["part_struct_constant"] == PART_STRUCT_CONSTANT
                for item in members),
            "name_padding_ok": all(item["name_padding_ok"] for item in members),
        }

        size_ok = True
        preceding_ok = True
        running = 0
        for item in members:
            if item["part_size"] != item["file_size"]:
                size_ok = False
            if item["preceding_size"] != running:
                preceding_ok = False
            running += item["file_size"]
        checks["part_size_equals_file_size"] = size_ok
        checks["preceding_size_is_running_sum"] = preceding_ok
        observed_total = running
        declared_total = members[0]["total_size"]
        checks["total_size_equals_sum_of_parts"] = observed_total == declared_total

        entry = {
            "database": key,
            "part_count": len(members),
            "format_version": ".".join(str(v) for v in members[0]["format_version"][:3]),
            "database_id": members[0]["database_id"],
            "build_id": members[0]["build_id"],
            "declared_total_size": declared_total,
            "observed_total_size": observed_total,
            "total_size_delta": declared_total - observed_total,
            "checks": checks,
            "parts": [
                {
                    "file": Path(item["file"]).name,
                    "part_index": item["part_index"],
                    "part_size": item["part_size"],
                    "preceding_size": item["preceding_size"],
                }
                for item in members
            ],
        }
        results.append(entry)
        for check_name, ok in checks.items():
            if not ok:
                failures.append(f"{key}: {check_name}")

    return {"databases": results, "failures": failures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pkgdb", type=Path, help="pkgdb koren sa */*.ATLAS")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    paths = sorted(args.pkgdb.glob("*/*.ATLAS"))
    if not paths:
        print("nema ATLAS fajlova", file=sys.stderr)
        return 1

    headers = [decode_header(path) for path in paths]
    report = verify(headers)
    report["schema_version"] = 1
    report["headers"] = headers
    report["boundary"] = (
        "Polja 0x3c/0x3e i build_id nisu imenovana; database_id je posmatran, "
        "ne protumacen.  Sve velicinske relacije su provereno tacne."
    )

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False))
    lines = []
    for item in sorted(args.output.iterdir()):
        if item.is_file() and item.name != "CHECKSUMS.sha256":
            lines.append(f"{hashlib.sha256(item.read_bytes()).hexdigest()}  {item.name}")
    (args.output / "CHECKSUMS.sha256").write_text("\n".join(lines) + "\n")

    for entry in report["databases"]:
        failed = [k for k, v in entry["checks"].items() if not v]
        status = "OK" if not failed else "PAD: " + ", ".join(failed)
        print(f"{entry['database']:<34} v{entry['format_version']:<7} "
              f"delova={entry['part_count']}  ukupno={entry['observed_total_size']:>13,}  "
              f"delta={entry['total_size_delta']:>10,}  {status}")
    print()
    print(f"neuspelih provera: {len(report['failures'])}")
    return 1 if report["failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
