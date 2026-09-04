#!/usr/bin/env python3
"""Decode and validate direct Basic handle-2 SDString sequences.

The cursor grammar mirrors firmware VA 0x014915e8/0x01491fac.  Each unique
record owns a direct string sequence between its fixed header and its first
flag-selected section.  Cluster header bits select identifier prefixes,
primary encoding, and optional phonetic/secondary strings.
"""

from __future__ import annotations

import argparse
import collections
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys

from basic_handle2_directory import (
    FIRMWARE_RECORD_POINTER_BASE,
    _group_entries,
    _record_header,
    decode_edge_directory,
    decode_record_data_end,
)
from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 1

# These external schema-descriptor values are not stored in the handle-2
# payload.  They are inferred below only if the full corpus ends exactly at
# every independently bounded direct-string section.
PRIMARY_STRING_COUNT = 1
ALTERNATE_STRING_COUNT = 1
ALTERNATE_ENCODING = 1
SECONDARY_STRING_COUNT = 1
SECONDARY_ENCODING = 1


@dataclass(frozen=True)
class TextSchema:
    tagged: bool
    secondary_present: bool
    secondary_tagged: bool
    default_identifier: int
    primary_encoding: int
    alternate_encoding: int = ALTERNATE_ENCODING
    secondary_encoding: int = SECONDARY_ENCODING
    primary_count: int = PRIMARY_STRING_COUNT
    alternate_count: int = ALTERNATE_STRING_COUNT
    secondary_count: int = SECONDARY_STRING_COUNT


@dataclass(frozen=True)
class TextEntry:
    identifier: int
    alternate: bool
    primary: tuple[str, ...]
    secondary_identifier: int | None
    secondary: tuple[str, ...]
    start: int
    end: int


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(
        f"handle2-text stage={stage}{' ' if suffix else ''}{suffix}",
        file=sys.stderr,
        flush=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def schema_from_payload(payload: bytes) -> TextSchema:
    if len(payload) < 6:
        raise PsfError("handle-2 payload is truncated before its text schema")
    encoding = (payload[3] & 0x18) >> 3
    if encoding > 2:
        raise PsfError(f"unsupported direct-string encoding {encoding}")
    return TextSchema(
        tagged=bool(payload[3] & 0x01),
        secondary_present=bool(payload[3] & 0x04),
        # Firmware copies this bit into descriptor byte 3 when the external
        # Basic-v60 schema enables the secondary-identifier field.
        secondary_tagged=bool(payload[5] & 0x01),
        default_identifier=payload[4],
        primary_encoding=encoding,
    )


def _decode_terminated(
    data: bytes, cursor: int, end: int, encoding: int
) -> tuple[str, int]:
    if not 0 <= cursor <= end <= len(data):
        raise PsfError("invalid SDString bounds")
    if encoding in (0, 1):
        terminator = data.find(b"\x00", cursor, end)
        if terminator < 0:
            raise PsfError("unterminated one-byte SDString")
        codec = "latin-1" if encoding == 0 else "utf-8"
        try:
            value = data[cursor:terminator].decode(codec, errors="strict")
        except UnicodeDecodeError as error:
            raise PsfError(f"invalid {codec} SDString: {error}") from error
        return value, terminator + 1
    if encoding == 2:
        terminator = cursor
        while terminator + 1 < end and data[terminator : terminator + 2] != b"\x00\x00":
            terminator += 2
        if terminator + 1 >= end:
            raise PsfError("unterminated UTF-16LE SDString")
        try:
            value = data[cursor:terminator].decode("utf-16le", errors="strict")
        except UnicodeDecodeError as error:
            raise PsfError(f"invalid UTF-16LE SDString: {error}") from error
        return value, terminator + 2
    raise PsfError(f"unsupported SDString encoding {encoding}")


def decode_text_entry(
    data: bytes, cursor: int, end: int, schema: TextSchema
) -> TextEntry:
    start = cursor
    if schema.tagged:
        if cursor >= end:
            raise PsfError("truncated SDString identifier")
        encoded_identifier = data[cursor]
        cursor += 1
        identifier = encoded_identifier & 0x7F
        alternate = bool(encoded_identifier & 0x80)
    else:
        identifier = schema.default_identifier
        alternate = False
    primary_count = schema.alternate_count if alternate else schema.primary_count
    primary_encoding = (
        schema.alternate_encoding if alternate else schema.primary_encoding
    )
    primary: list[str] = []
    for _ in range(primary_count):
        value, cursor = _decode_terminated(data, cursor, end, primary_encoding)
        primary.append(value)

    secondary_identifier: int | None = None
    secondary: list[str] = []
    if schema.secondary_present:
        if schema.secondary_tagged:
            if cursor >= end:
                raise PsfError("truncated secondary SDString identifier")
            secondary_identifier = data[cursor] & 0x7F
            cursor += 1
        else:
            secondary_identifier = schema.default_identifier
        for _ in range(schema.secondary_count):
            value, cursor = _decode_terminated(
                data, cursor, end, schema.secondary_encoding
            )
            secondary.append(value)
    return TextEntry(
        identifier,
        alternate,
        tuple(primary),
        secondary_identifier,
        tuple(secondary),
        start,
        cursor,
    )


def decode_direct_texts(
    payload: bytes,
    record_offset: int,
    record_end: int,
    schema: TextSchema,
) -> tuple[TextEntry, ...]:
    header = _record_header(
        payload,
        record_offset,
        FIRMWARE_RECORD_POINTER_BASE,
        record_end,
    )
    if not header["header_fits"]:
        raise PsfError("truncated handle-2 record header")
    pointers = header["pointers"]
    assert isinstance(pointers, list)
    section_end = min(
        (int(pointer["absolute_offset"]) for pointer in pointers),
        default=record_end,
    )
    cursor = int(header["count_offset"]) + 1
    count = header["main_count"]
    assert isinstance(count, int)
    entries: list[TextEntry] = []
    for _ in range(count):
        entry = decode_text_entry(payload, cursor, section_end, schema)
        entries.append(entry)
        cursor = entry.end
    if cursor != section_end:
        trailing = payload[cursor:section_end]
        raise PsfError(
            f"direct SDString cursor stopped {len(trailing)} byte(s) before "
            f"section end; trailing={trailing[:16].hex()}"
        )
    return tuple(entries)


def _entry_fields(entry: TextEntry, record_offset: int) -> dict[str, object]:
    return {
        "identifier": entry.identifier,
        "alternate": entry.alternate,
        "primary": list(entry.primary),
        "secondary_identifier": entry.secondary_identifier,
        "secondary": list(entry.secondary),
        "relative_start": entry.start - record_offset,
        "relative_end": entry.end - record_offset,
    }


def run(psf: Path, output: Path, sample_limit: int) -> dict[str, object]:
    if sample_limit < 0:
        raise ValueError("sample limit must be zero or positive")
    _progress("index")
    index = read_basic_triple_handle_index(psf)
    order, grouped = _group_entries(index)
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "edge_texts.jsonl"
    sample_temporary = sample_path.with_suffix(sample_path.suffix + ".tmp")

    counts = collections.Counter()
    counts["decode_failures"] = 0
    payload_header_3 = collections.Counter()
    payload_header_4 = collections.Counter()
    payload_header_5 = collections.Counter()
    identifiers = collections.Counter()
    primary_values = collections.Counter()
    secondary_values = collections.Counter()
    encoding_profiles = collections.Counter()
    failures: list[dict[str, object]] = []
    emitted = 0
    _progress("decode", clusters_total=len(order))
    with psf.open("rb") as source, sample_temporary.open(
        "w", encoding="utf-8"
    ) as destination:
        for ordinal, cluster_id in enumerate(order, 1):
            topology = _decode_indexed_lzma(source, grouped[cluster_id][0])
            payload = _decode_indexed_lzma(source, grouped[cluster_id][2])
            if len(topology) < 5:
                raise PsfError(f"cluster {cluster_id} has truncated topology")
            directory = decode_edge_directory(payload, topology[2])
            record_data_end = decode_record_data_end(
                payload, directory.directory_end
            )
            schema = schema_from_payload(payload)
            payload_header_3[payload[3]] += 1
            payload_header_4[payload[4]] += 1
            payload_header_5[payload[5]] += 1
            encoding_profiles[
                (
                    int(schema.tagged),
                    int(schema.secondary_present),
                    int(schema.secondary_tagged),
                    schema.primary_encoding,
                )
            ] += 1
            unique_offsets = sorted(set(directory.record_offsets))
            record_ends = {
                record_offset: (
                    unique_offsets[index + 1]
                    if index + 1 < len(unique_offsets)
                    else record_data_end
                )
                for index, record_offset in enumerate(unique_offsets)
            }
            decoded_by_offset: dict[int, tuple[TextEntry, ...]] = {}
            for record_offset in unique_offsets:
                counts["unique_records"] += 1
                try:
                    entries = decode_direct_texts(
                        payload,
                        record_offset,
                        record_ends[record_offset],
                        schema,
                    )
                except PsfError as error:
                    counts["decode_failures"] += 1
                    if len(failures) < 100:
                        failures.append(
                            {
                                "cluster_id": cluster_id,
                                "record_offset": record_offset,
                                "record_end": record_ends[record_offset],
                                "payload_header_hex": payload[:8].hex(),
                                "record_hex": payload[
                                    record_offset : min(
                                        record_ends[record_offset], record_offset + 128
                                    )
                                ].hex(),
                                "error": str(error),
                            }
                        )
                    entries = ()
                decoded_by_offset[record_offset] = entries
                counts["text_entries"] += len(entries)
                for entry in entries:
                    identifiers[entry.identifier] += 1
                    counts["primary_strings"] += len(entry.primary)
                    counts["secondary_strings"] += len(entry.secondary)
                    counts["alternate_entries"] += int(entry.alternate)
                    primary_values.update(entry.primary)
                    secondary_values.update(entry.secondary)
            for edge_index, record_offset in enumerate(directory.record_offsets):
                counts["edges"] += 1
                entries = decoded_by_offset[record_offset]
                if sample_limit and emitted >= sample_limit:
                    continue
                destination.write(
                    json.dumps(
                        {
                            "schema_version": SCHEMA_VERSION,
                            "record_type": "mib-basic-handle2-edge-texts",
                            "cluster_id": cluster_id,
                            "edge_index": edge_index,
                            "edge_id": (cluster_id << 8) | edge_index,
                            "edge_id_hex": f"0x{((cluster_id << 8) | edge_index):08x}",
                            "record_offset": record_offset,
                            "texts": [
                                _entry_fields(entry, record_offset)
                                for entry in entries
                            ],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + "\n"
                )
                emitted += 1
            counts["clusters"] += 1
            if ordinal % 250 == 0 or ordinal == len(order):
                _progress("decode-progress", clusters=ordinal, total=len(order))
    sample_temporary.replace(sample_path)

    status = "direct-text-validated" if not failures else "schema-candidate-rejected"
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "input": {
            "path": str(psf.resolve()),
            "size": psf.stat().st_size,
            "sha256": _sha256(psf),
        },
        "firmware_evidence": {
            "sdstring_decoders": ["0x014915e8", "0x01491fac"],
            "tagged_from_payload_byte_3_bit_0": True,
            "secondary_from_payload_byte_3_bit_2": True,
            "primary_encoding_from_payload_byte_3_bits_3_4": True,
        },
        "external_schema_candidate": {
            "primary_string_count": PRIMARY_STRING_COUNT,
            "alternate_string_count": ALTERNATE_STRING_COUNT,
            "alternate_encoding": ALTERNATE_ENCODING,
            "secondary_string_count": SECONDARY_STRING_COUNT,
            "secondary_encoding": SECONDARY_ENCODING,
            "secondary_tagged": "payload_byte_5_bit_0",
            "encoding_values": {"0": "Latin-1", "1": "UTF-8", "2": "UTF-16LE"},
        },
        "counts": dict(sorted(counts.items())),
        "histograms": {
            "payload_byte_3": {
                f"0x{key:02x}": value for key, value in payload_header_3.most_common()
            },
            "payload_byte_4": {
                f"0x{key:02x}": value for key, value in payload_header_4.most_common()
            },
            "payload_byte_5": {
                f"0x{key:02x}": value for key, value in payload_header_5.most_common()
            },
            "encoding_profile": {
                "/".join(map(str, key)): value
                for key, value in encoding_profiles.most_common()
            },
            "identifier": {
                str(key): value for key, value in identifiers.most_common()
            },
        },
        "most_common": {
            "primary": [
                {"value": value, "count": count}
                for value, count in primary_values.most_common(100)
            ],
            "secondary": [
                {"value": value, "count": count}
                for value, count in secondary_values.most_common(100)
            ],
        },
        "failures": failures,
        "artifacts": {
            "report": "report.json",
            "edge_texts": sample_path.name,
            "edge_text_count": emitted,
            "checksums": "CHECKSUMS.sha256",
        },
    }
    report_path = output / "report.json"
    report_temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    report_temporary.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n"
        f"{_sha256(sample_path)}  {sample_path.name}\n",
        encoding="ascii",
    )
    _progress(
        "complete",
        status=status,
        records=counts["unique_records"],
        failures=counts["decode_failures"],
    )
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sample-limit", type=int, default=100)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(args.psf, args.output, args.sample_limit)
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_handle2_text_decode: {error}", file=sys.stderr)
        return 1
    counts = report["counts"]
    assert isinstance(counts, dict)
    print(
        json.dumps(
            {
                "status": report["status"],
                "clusters": counts["clusters"],
                "edges": counts["edges"],
                "unique_records": counts["unique_records"],
                "decode_failures": counts["decode_failures"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "direct-text-validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
