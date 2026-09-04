#!/usr/bin/env python3
"""Infer and validate the nested subrecord grammar inside Basic geometry records."""

from __future__ import annotations

import argparse
import collections
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct
import sys
from typing import BinaryIO

from basic_semantic_probe import geometry_record_offsets
from psf_decode import PsfError, _decode_indexed_lzma, read_basic_triple_handle_index


SCHEMA_VERSION = 1
HEADER_BASE_CANDIDATES = range(1, 17)
SUBRECORD_BASE_CANDIDATES = range(1, 33)
SUBRECORD_STRIDE_CANDIDATES = range(0, 17)


@dataclass(frozen=True)
class GeometryRecord:
    cluster_id: int
    edge_index: int
    cluster_flags: int
    decoded_offset: int
    data: bytes


@dataclass(frozen=True)
class Grammar:
    record_header_base: int
    subrecord_base: int
    subrecord_stride: int


def _progress(stage: str, **values: object) -> None:
    suffix = " ".join(f"{key}={value}" for key, value in values.items())
    print(f"geometry-grammar stage={stage}{' ' if suffix else ''}{suffix}", file=sys.stderr, flush=True)


def _first_subrecord_offset(record: bytes, header_base: int) -> int | None:
    if len(record) < 2:
        return None
    flags = record[0]
    if flags & 0x80:
        if header_base >= len(record):
            return None
        return record[header_base]
    mode = (flags & 0x3F) >> 4
    prefix = 1 if mode == 1 else 4 if mode == 2 else 0
    return header_base + prefix + (4 if flags & 0x40 else 0)


def split_subrecords(record: bytes, cluster_flags: int, grammar: Grammar) -> list[tuple[int, int]] | None:
    if len(record) < 2:
        return None
    count = record[1]
    cursor = _first_subrecord_offset(record, grammar.record_header_base)
    if cursor is None:
        return None
    if count == 0:
        return [] if cursor == len(record) else None
    result: list[tuple[int, int]] = []
    coordinate_width = 8 if cluster_flags & 1 else 4
    for subrecord_index in range(count):
        if cursor + 3 > len(record):
            return None
        # The firmware advances by the current subrecord length only when it
        # needs the next subrecord.  The enclosing edge offset table supplies
        # the final boundary, so do not invent a length for the last member.
        if subrecord_index + 1 == count:
            result.append((cursor, len(record)))
            return result
        flags = record[cursor]
        length = grammar.subrecord_base + grammar.subrecord_stride * record[cursor + 2]
        if not flags & 1:
            length += coordinate_width
        if not flags & 2:
            length += coordinate_width
        if record[cursor + 1] & 0x80:
            if cursor + length + 2 > len(record):
                return None
            length += 2 + struct.unpack_from("<H", record, cursor + length)[0]
        if length <= 0 or cursor + length > len(record):
            return None
        result.append((cursor, cursor + length))
        cursor += length
    return result


def _decode_records(psf: Path) -> tuple[list[GeometryRecord], dict[str, object]]:
    index = read_basic_triple_handle_index(psf)
    entries = [
        entry for entry in index["entries"] if int(entry["handle_index"]) == 1
    ]
    records: list[GeometryRecord] = []
    flag_counts = collections.Counter()
    with psf.open("rb") as source:
        for ordinal, entry in enumerate(entries, 1):
            payload = _decode_indexed_lzma(source, entry)
            offsets, required_end = geometry_record_offsets(payload, 24)
            if not offsets or offsets[0] < required_end or offsets != sorted(set(offsets)):
                raise PsfError(f"invalid geometry offsets in cluster {entry['cluster_id']}")
            ends = offsets[1:] + [len(payload)]
            cluster_flags = payload[20]
            flag_counts[cluster_flags] += 1
            for edge_index, (start, end) in enumerate(zip(offsets, ends)):
                records.append(
                    GeometryRecord(
                        cluster_id=int(entry["cluster_id"]),
                        edge_index=edge_index,
                        cluster_flags=cluster_flags,
                        decoded_offset=start,
                        data=payload[start:end],
                    )
                )
            if ordinal % 250 == 0 or ordinal == len(entries):
                _progress("decode-progress", clusters=ordinal, total=len(entries), records=len(records))
    return records, {
        "clusters": len(entries),
        "geometry_records": len(records),
        "cluster_flag_values": {str(key): value for key, value in sorted(flag_counts.items())},
    }


def _infer_grammar(records: list[GeometryRecord], inference_limit: int) -> tuple[Grammar, dict[str, object]]:
    candidates = {
        Grammar(header, base, stride)
        for header in HEADER_BASE_CANDIDATES
        for base in SUBRECORD_BASE_CANDIDATES
        for stride in SUBRECORD_STRIDE_CANDIDATES
    }
    inspected = 0
    checkpoints = {1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
    maximum = min(len(records), inference_limit) if inference_limit else len(records)
    for record in records[:maximum]:
        inspected += 1
        candidates = {
            grammar
            for grammar in candidates
            if split_subrecords(record.data, record.cluster_flags, grammar) is not None
        }
        if inspected in checkpoints or len(candidates) <= 10:
            _progress("infer-progress", records=inspected, candidates=len(candidates))
        if len(candidates) <= 1:
            break
    if len(candidates) != 1:
        preview = [
            {
                "record_header_base": item.record_header_base,
                "subrecord_base": item.subrecord_base,
                "subrecord_stride": item.subrecord_stride,
            }
            for item in sorted(
                candidates,
                key=lambda item: (
                    item.record_header_base,
                    item.subrecord_base,
                    item.subrecord_stride,
                ),
            )[:100]
        ]
        raise PsfError(
            f"geometry grammar is not unique after {inspected} records; "
            f"survivors={len(candidates)} preview={preview}"
        )
    grammar = next(iter(candidates))
    return grammar, {
        "records_used": inspected,
        "initial_candidate_count": (
            len(HEADER_BASE_CANDIDATES)
            * len(SUBRECORD_BASE_CANDIDATES)
            * len(SUBRECORD_STRIDE_CANDIDATES)
        ),
        "survivor_count": 1,
    }


def _validate(records: list[GeometryRecord], grammar: Grammar) -> dict[str, object]:
    subrecord_counts = collections.Counter()
    record_flag_counts = collections.Counter()
    subrecord_flag_counts = collections.Counter()
    delta_pair_count_values = collections.Counter()
    extension_subrecords = 0
    total_subrecords = 0
    maximum_record_size = 0
    maximum_subrecord_size = 0
    failures: list[dict[str, object]] = []
    for ordinal, record in enumerate(records, 1):
        parts = split_subrecords(record.data, record.cluster_flags, grammar)
        if parts is None:
            if len(failures) < 100:
                failures.append(
                    {
                        "cluster_id": record.cluster_id,
                        "edge_index": record.edge_index,
                        "record_size": len(record.data),
                        "record_prefix_hex": record.data[:64].hex(),
                    }
                )
            continue
        subrecord_counts[len(parts)] += 1
        record_flag_counts[record.data[0]] += 1
        maximum_record_size = max(maximum_record_size, len(record.data))
        total_subrecords += len(parts)
        for start, end in parts:
            subrecord_flag_counts[record.data[start]] += 1
            delta_pair_count_values[record.data[start + 2]] += 1
            extension_subrecords += int(bool(record.data[start + 1] & 0x80))
            maximum_subrecord_size = max(maximum_subrecord_size, end - start)
        if ordinal % 100_000 == 0 or ordinal == len(records):
            _progress("validate-progress", records=ordinal, total=len(records), failures=len(failures))
    return {
        "all_records_split_exactly": not failures,
        "failure_count": len(failures),
        "failure_examples": failures,
        "total_subrecords": total_subrecords,
        "extension_subrecords": extension_subrecords,
        "maximum_geometry_record_size": maximum_record_size,
        "maximum_subrecord_size": maximum_subrecord_size,
        "subrecords_per_geometry_record": {
            str(key): value for key, value in sorted(subrecord_counts.items())
        },
        "geometry_record_flag_values": {
            str(key): value for key, value in sorted(record_flag_counts.items())
        },
        "subrecord_flag_values": {
            str(key): value for key, value in sorted(subrecord_flag_counts.items())
        },
        "delta_pair_count_values": {
            str(key): value for key, value in sorted(delta_pair_count_values.items())
        },
    }


def _write_samples(
    path: Path,
    records: list[GeometryRecord],
    grammar: Grammar,
    limit: int,
) -> int:
    temporary = path.with_suffix(path.suffix + ".tmp")
    emitted = 0
    with temporary.open("w", encoding="utf-8") as destination:
        for record in records:
            parts = split_subrecords(record.data, record.cluster_flags, grammar)
            if parts is None:
                continue
            item = {
                "schema_version": SCHEMA_VERSION,
                "record_type": "basic-geometry-grammar-source",
                "cluster_id": record.cluster_id,
                "edge_index": record.edge_index,
                "edge_id": (record.cluster_id << 8) | record.edge_index,
                "cluster_flags": record.cluster_flags,
                "record_decoded_offset": record.decoded_offset,
                "record_size": len(record.data),
                "record_sha256": hashlib.sha256(record.data).hexdigest(),
                "record_header_hex": record.data[: parts[0][0]].hex() if parts else record.data.hex(),
                "subrecords": [
                    {
                        "index": index,
                        "offset": start,
                        "size": end - start,
                        "flags": record.data[start],
                        "secondary_flags": record.data[start + 1],
                        "delta_pair_count": record.data[start + 2],
                        "hex": record.data[start:end].hex(),
                    }
                    for index, (start, end) in enumerate(parts)
                ],
            }
            destination.write(json.dumps(item, sort_keys=True) + "\n")
            emitted += 1
            if limit and emitted >= limit:
                break
    temporary.replace(path)
    return emitted


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run(psf: Path, output: Path, inference_limit: int, sample_limit: int) -> dict[str, object]:
    _progress("decode")
    records, counts = _decode_records(psf)
    _progress("infer", records=min(len(records), inference_limit or len(records)))
    grammar, inference = _infer_grammar(records, inference_limit)
    _progress(
        "grammar",
        record_header_base=grammar.record_header_base,
        subrecord_base=grammar.subrecord_base,
        subrecord_stride=grammar.subrecord_stride,
    )
    validation = _validate(records, grammar)
    report: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "status": "validated" if validation["all_records_split_exactly"] else "validation-failed",
        "input": {"path": str(psf.resolve()), "size": psf.stat().st_size},
        "scope": {
            "index_kind": "basic-id-triple",
            "handle_index": 1,
            "geometry_record_offset_table_base": 24,
            "semantic_limit": "this stage validates subrecord boundaries; basic_geometry_decode.py decodes coordinates, while extensions remain typed raw data",
        },
        "counts": counts,
        "grammar": {
            "record_header_base": grammar.record_header_base,
            "subrecord_base": grammar.subrecord_base,
            "subrecord_stride": grammar.subrecord_stride,
            "subrecord_byte_2": "count of signed int8 x/y delta pairs",
            "coordinate_pair_width_u16_components": 4,
            "coordinate_pair_width_u32_components": 8,
            "endpoint_presence_flags": "subrecord byte 0 bits 0/1",
            "extension_flag": "subrecord byte 1 bit 7",
        },
        "inference": inference,
        "validation": validation,
        "evidence": {
            "firmware_consumer_ghidra_va": "0x01553940",
            "core_length_helper_ghidra_va": "0x002e62b4",
            "extension_length_helper_ghidra_va": "0x0149d144",
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    sample_path = output / "geometry_sample.jsonl"
    sample_count = _write_samples(sample_path, records, grammar, sample_limit)
    report["artifacts"] = {
        "report": "report.json",
        "geometry_sample": sample_path.name,
        "geometry_sample_count": sample_count,
        "checksums": "CHECKSUMS.sha256",
    }
    report_path = output / "report.json"
    temporary = report_path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(report_path)
    (output / "CHECKSUMS.sha256").write_text(
        f"{_sha256(report_path)}  {report_path.name}\n{_sha256(sample_path)}  {sample_path.name}\n",
        encoding="ascii",
    )
    _progress("complete", status=report["status"], output=output)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("psf", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--inference-record-limit",
        type=int,
        default=10_000,
        help="0 may use every record; inference normally converges early",
    )
    parser.add_argument("--sample-limit", type=int, default=100)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = run(
            args.psf,
            args.output,
            args.inference_record_limit,
            args.sample_limit,
        )
    except (OSError, PsfError, ValueError) as error:
        print(f"basic_geometry_grammar: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": report["status"],
                "geometry_records": report["counts"]["geometry_records"],  # type: ignore[index]
                "total_subrecords": report["validation"]["total_subrecords"],  # type: ignore[index]
                "grammar": report["grammar"],
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "validated" else 2


if __name__ == "__main__":
    raise SystemExit(main())
